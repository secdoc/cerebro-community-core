import json
import fcntl
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from security_portal.config import ConfigError, load_config
from security_portal.connectors import collect_integration
from scripts.install import finish_apply, finish_rollback, gate_check

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_github_dry_run_uses_absent_isolated_root(self):
        workflow = (ROOT / '.github/workflows/verify.yml').read_text()
        self.assertIn('python3 scripts/install.py --root "$RUNNER_TEMP/cerebro-dry-run-root" --config examples/config.json --dry-run', workflow)

    def test_ui_declares_self_contained_favicon(self):
        from html.parser import HTMLParser
        from security_portal.server import PortalHandler

        class IconLinks(HTMLParser):
            icons = []

            def handle_starttag(self, tag, attrs):
                if tag == 'link' and dict(attrs).get('rel') == 'icon':
                    self.icons.append(dict(attrs).get('href'))

        parser = IconLinks()
        parser.feed((ROOT / 'security_portal/static/index.html').read_text())
        self.assertEqual(len(parser.icons), 1)
        self.assertTrue(parser.icons[0].startswith('data:image/svg+xml,'))
        from urllib.parse import unquote
        from xml.etree import ElementTree
        icon = ElementTree.fromstring(unquote(parser.icons[0].partition(',')[2]))
        self.assertEqual(icon.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertTrue(any("img-src 'self' data:" in value for value in PortalHandler.end_headers.__code__.co_consts if isinstance(value, str)))

    def config(self, integration):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps({'portal': {'title': 'Cerebro'}, 'integrations': [integration]}))
            return load_config(path)

    def base(self):
        return {'id': 'feed', 'name': 'Feed', 'category': 'SOC', 'connector': 'http_json',
                'url': 'https://feed.example.com/status', 'allowed_origins': ['https://feed.example.com'],
                'max_age_seconds': 60, 'summary_paths': {'count': 'count'}}

    def test_rejects_non_get_and_cross_origin(self):
        spec = self.base(); spec['method'] = 'POST'
        with self.assertRaises(ConfigError): self.config(spec)
        spec = self.base(); spec['url'] = 'https://other.example.com/status'
        with self.assertRaises(ConfigError): self.config(spec)

    def test_allowed_origins_rejects_paths_and_parameters(self):
        for origin in ('https://feed.example.com/status', 'https://feed.example.com/;scope=admin'):
            spec = self.base(); spec['allowed_origins'] = [origin]
            with self.subTest(origin=origin), self.assertRaisesRegex(ConfigError, 'exact HTTPS origin'):
                self.config(spec)
        spec = self.base(); spec['allowed_origins'] = ['https://feed.example.com/']
        self.assertEqual(self.config(spec)['integrations'][0]['allowed_origins'], spec['allowed_origins'])

    def test_rejects_arbitrary_header_and_unbounded_analytics(self):
        spec = self.base(); spec['header_env'] = {'Host': 'TOKEN'}
        with self.assertRaises(ConfigError): self.config(spec)
        spec = self.base(); spec['analytics_paths'] = {'secrets': 'all'}
        with self.assertRaises(ConfigError): self.config(spec)

    def test_rejects_local_metadata_and_private_network_targets(self):
        for url in ['http://' + '.'.join(['169','254','169','254']) + '/latest', 'http://localhost/status',
                    'https://' + '.'.join(['10','1','2','3']) + '/status', 'https://feed.example.com:443@evil.example/status']:
            spec = self.base(); spec['url'] = url; spec['allowed_origins'] = [url]
            with self.subTest(url=url), self.assertRaises(ConfigError): self.config(spec)

    def test_rejects_query_strings_on_credential_free_urls(self):
        for field in ('url', 'allowed_origins', 'deep_link'):
            spec = self.base()
            if field == 'allowed_origins':
                spec[field] = ['https://feed.example.com/?access_token=sensitive']
            else:
                spec[field] = 'https://feed.example.com/status?access_token=sensitive'
            with self.subTest(field=field), self.assertRaises(ConfigError):
                self.config(spec)

    def test_rejects_symlink_snapshot_and_non_scalar_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'secret').write_text('{"count":{"password":"not-for-publication"}}')
            (root/'link').symlink_to(root/'secret')
            spec = {'id':'feed','name':'Feed','category':'SOC','connector':'json_file',
                    'path':str(root/'link'),'max_age_seconds':60,'summary_paths':{'count':'count'}}
            self.assertEqual(collect_integration(spec)['state'], 'unavailable')
            spec['path'] = str(root/'secret')
            self.assertNotIn('count', collect_integration(spec)['summary'])

    def test_snapshot_read_is_descriptor_bound_and_size_limited(self):
        from security_portal import connectors
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root/'snapshot.json'
            secret = root/'secret.json'
            snapshot.write_text('{"count":1}')
            secret.write_text('{"count":98765}')
            spec = {'id':'feed','name':'Feed','category':'SOC','connector':'json_file',
                    'path':str(snapshot),'max_age_seconds':60,'summary_paths':{'count':'count'}}
            self.assertEqual(collect_integration(spec)['summary']['count'], 1)
            fifo = root/'pipe'
            os.mkfifo(fifo)
            spec['path'] = str(fifo)
            self.assertEqual(collect_integration(spec)['state'], 'unavailable')
            spec['path'] = str(snapshot)
            original_open = connectors.os.open
            def swap_before_open(path, flags, *args, **kwargs):
                snapshot.unlink()
                snapshot.symlink_to(secret)
                return original_open(path, flags, *args, **kwargs)
            with patch.object(connectors.os, 'open', side_effect=swap_before_open):
                self.assertEqual(collect_integration(spec)['state'], 'unavailable')
            snapshot.unlink()
            snapshot.write_text('{"count":1,"padding":"' + 'x' * (1024 * 1024) + '"}')
            self.assertEqual(collect_integration(spec)['state'], 'unavailable')


class InstallerTests(unittest.TestCase):
    def test_apply_reload_failure_retains_pending_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'previous.json'
            pending = {'_format': 1, 'status': 'pending', 'targets': {'etc/cerebro/config.json': None}}
            state.write_text(json.dumps(pending))
            failure = subprocess.CalledProcessError(1, ['systemctl', 'daemon-reload'])
            with patch('scripts.install.subprocess.run', side_effect=failure) as reload:
                with self.assertRaises(subprocess.CalledProcessError):
                    finish_apply(state, pending['targets'], Path('/'))
            reload.assert_called_once_with(['systemctl', 'daemon-reload'], check=True)
            self.assertEqual(json.loads(state.read_text()), pending)

    def test_rollback_receipt_survives_daemon_reload_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / 'previous.json'
            receipt.write_text('recovery-point')
            failure = subprocess.CalledProcessError(1, ['systemctl', 'daemon-reload'])
            with patch('scripts.install.subprocess.run', side_effect=failure) as reload:
                with self.assertRaises(subprocess.CalledProcessError):
                    finish_rollback(receipt, Path('/'))
            reload.assert_called_once_with(['systemctl', 'daemon-reload'], check=True)
            self.assertEqual(receipt.read_text(), 'recovery-point')
            with patch('scripts.install.subprocess.run') as reload:
                finish_rollback(receipt, Path('/'))
            reload.assert_called_once_with(['systemctl', 'daemon-reload'], check=True)
            self.assertFalse(receipt.exists())

    def test_apply_waits_for_exclusive_installer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'root'
            dest.mkdir(mode=0o700)
            lock = dest / '.cerebro-installer.lock'
            fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            proc = subprocess.Popen([sys.executable, str(ROOT / 'scripts/install.py'),
                                     '--root', str(dest), '--config',
                                     str(ROOT / 'examples/config.json'), '--apply'],
                                    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
            try:
                time.sleep(0.3)
                self.assertIsNone(proc.poll(), 'installer did not wait for the held lock')
                self.assertFalse((dest / 'var/lib/cerebro-installer/previous.json').exists())
                self.assertFalse((dest / 'opt/cerebro/security_portal/server.py').exists())
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            stdout, stderr = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn('installed=complete', stdout)
            self.assertEqual(json.loads((dest / 'var/lib/cerebro-installer/previous.json').read_text())['status'], 'complete')
            self.assertTrue((dest / 'opt/cerebro/security_portal/server.py').exists())

    def test_installer_refuses_symlink_lock_without_target_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'root'
            dest.mkdir()
            outside = Path(tmp) / 'outside'
            outside.write_text('untouched')
            (dest / '.cerebro-installer.lock').symlink_to(outside)
            result = self.run_install('--root', str(dest), '--config',
                                      str(ROOT / 'examples/config.json'), '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(outside.read_text(), 'untouched')
            self.assertFalse((dest / 'var').exists())

    def test_activation_gate_refuses_query_and_fragment_without_network(self):
        for suffix in ('?access_token=sentinel', '#access_token=sentinel'):
            with self.subTest(suffix=suffix), patch('scripts.install.urllib.request.build_opener') as opener:
                with self.assertRaisesRegex(ValueError, 'credential-free'):
                    gate_check('https://proxy.example.com/' + suffix)
                opener.assert_not_called()

    def test_privacy_scanner_detects_generated_private_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture=Path(tmp)/'payload.example'
            fixture.write_text('controller.'+'corp.'+'internal'+'\n'+'10.'+'19.'+'24.'+'5'+'\n')
            result=subprocess.run([sys.executable,str(ROOT/'scripts/scrub.py'),tmp],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('private DNS',result.stdout)
            self.assertIn('private IP',result.stdout)

    def test_privacy_scanner_covers_ipv6_and_linked_worktree_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'.git').write_text('gitdir: /opt/data/cache/scratch/other-worktree\n')
            (root/'fixture.txt').write_text('fd00' + '::1\n')
            result = subprocess.run([sys.executable, str(ROOT/'scripts/scrub.py'), str(root)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn('private IPv6', result.stdout)
            self.assertNotIn('.git', result.stdout)

    def test_privacy_scanner_scans_its_own_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'scrub.py').write_text('controller.' + 'corp.' + 'internal\n')
            result = subprocess.run([sys.executable, str(ROOT/'scripts/scrub.py'), str(root)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn('private DNS', result.stdout)

    def test_privacy_scanner_handles_malformed_ipv4_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'payload.txt').write_text('.'.join(['999'] * 4) + '\n')
            result = subprocess.run([sys.executable, str(ROOT/'scripts/scrub.py'), tmp],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid IPv4', result.stdout)
            self.assertNotIn('Traceback', result.stderr)

    def test_wizard_generates_valid_adopter_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'config.json'
            answers='\n'.join(['Cerebro','Feed','feed','SOC','file', '600',
                               str(Path(tmp)/'feed.json'),'collected_at','healthy','events','count','',''])+'\n'
            command=[sys.executable,str(ROOT/'scripts/wizard.py'),'--output',str(output)]
            dry=subprocess.run(command,input=answers,capture_output=True,text=True)
            self.assertEqual(dry.returncode,0,dry.stderr)
            self.assertFalse(output.exists())
            applied=subprocess.run(command+['--apply'],input=answers,capture_output=True,text=True)
            self.assertEqual(applied.returncode,0,applied.stderr)
            self.assertEqual(load_config(output)['integrations'][0]['summary_paths'],{'events':'count'})
            self.assertEqual(output.stat().st_mode & 0o777,0o600)

    def test_wizard_records_adopter_dns_without_changing_host_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'config.json'
            resolver = '.'.join(('192', '0', '2', '53'))
            command = [sys.executable, str(ROOT/'scripts/wizard.py'), '--output', str(output),
                       '--dns-resolver', resolver, '--dns-resolver', '2001:db8::53',
                       '--dns-search-domain', 'site.example', '--apply']
            result = subprocess.run(command, input='Cerebro\n\n', capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            config = load_config(output)
            self.assertEqual(config['deployment']['dns_resolvers'], [resolver, '2001:db8::53'])
            self.assertEqual(config['deployment']['dns_search_domain'], 'site.example')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_wizard_refuses_invalid_adopter_dns_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'config.json'
            command = [sys.executable, str(ROOT/'scripts/wizard.py'), '--output', str(output),
                       '--dns-resolver', 'not-an-ip', '--apply']
            result = subprocess.run(command, input='Cerebro\n\n', capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_config_refuses_invalid_adopter_dns_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'config.json'
            resolver = '.'.join(('192', '0', '2', '53'))
            for deployment in ({'dns_resolvers': ['not-an-ip']},
                               {'dns_resolvers': [resolver, resolver]},
                               {'dns_search_domain': 'bad_domain.example'},
                               {'dns_resolvers': ['.'.join(('0', '0', '0', '0'))]}):
                with self.subTest(deployment=deployment):
                    path.write_text(json.dumps({'portal': {'title': 'Cerebro'},
                                                'integrations': [], 'deployment': deployment}))
                    with self.assertRaises(ConfigError): load_config(path)

    def run_install(self, *args):
        return subprocess.run([sys.executable, str(ROOT/'scripts/install.py'), *args], cwd=ROOT,
                              capture_output=True, text=True)

    def test_dry_run_has_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'root'
            result = self.run_install('--root', str(dest), '--config', str(ROOT/'examples/config.json'), '--dry-run')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(dest.exists())

    def test_install_idempotence_rollback_and_invalid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'root'; config = ROOT/'examples/config.json'
            first = self.run_install('--root', str(dest), '--config', str(config), '--apply')
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertTrue((dest/'etc/cerebro/config.json').exists())
            self.assertIn('127.0.0.1', (dest/'etc/systemd/system/cerebro.service').read_text())
            second = self.run_install('--root', str(dest), '--config', str(config), '--apply')
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn('changed=0', second.stdout)
            original = (dest/'etc/cerebro/config.json').read_bytes()
            changed = Path(tmp)/'changed.json'; content=json.loads(config.read_text()); content['portal']['title']='Changed'; changed.write_text(json.dumps(content))
            update = self.run_install('--root', str(dest), '--config', str(changed), '--apply')
            self.assertEqual(update.returncode, 0, update.stderr)
            self.assertEqual(self.run_install('--root', str(dest), '--rollback', '--apply').returncode, 0)
            self.assertEqual((dest/'etc/cerebro/config.json').read_bytes(), original)
            invalid=Path(tmp)/'invalid.json'; invalid.write_text('{oops')
            self.assertNotEqual(self.run_install('--root', str(dest), '--config', str(invalid), '--apply').returncode, 0)
            self.assertEqual((dest/'etc/cerebro/config.json').read_bytes(), original)

    def test_interrupted_apply_preserves_receipt_until_rollback(self):
        from scripts import install
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'root'
            config = str(ROOT/'examples/config.json')
            original_replace = install.os.replace
            written = []
            def fail_second_target(source, target):
                if Path(target).is_relative_to(dest/'opt/cerebro') or Path(target) == dest/'etc/cerebro/config.json':
                    written.append(str(target))
                    if len(written) == 2:
                        raise OSError('simulated interrupted write')
                return original_replace(source, target)
            with patch.object(sys, 'argv', ['install.py', '--root', str(dest), '--config', config, '--apply']), \
                 patch.object(install.os, 'replace', side_effect=fail_second_target):
                with self.assertRaisesRegex(OSError, 'simulated interrupted write'):
                    install.main()
            receipt = dest/'var/lib/cerebro-installer/previous.json'
            self.assertEqual(json.loads(receipt.read_text())['status'], 'pending')
            retry = self.run_install('--root', str(dest), '--config', config, '--apply')
            self.assertNotEqual(retry.returncode, 0)
            self.assertIn('interrupted installation', retry.stderr)
            rolled = self.run_install('--root', str(dest), '--rollback', '--apply')
            self.assertEqual(rolled.returncode, 0, rolled.stderr)
            self.assertFalse(receipt.exists())
            self.assertFalse((dest/'opt/cerebro/__init__.py').exists())
            self.assertEqual(self.run_install('--root', str(dest), '--config', config, '--apply').returncode, 0)

    def test_fresh_install_directories_support_unprivileged_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'root'
            result = self.run_install('--root', str(dest), '--config',
                                      str(ROOT / 'examples/config.json'), '--apply')
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ('opt', 'opt/cerebro', 'opt/cerebro/security_portal',
                         'opt/cerebro/security_portal/static'):
                self.assertEqual((dest / name).stat().st_mode & 0o005, 0o005, name)
            self.assertEqual((dest / 'etc/cerebro').stat().st_mode & 0o050, 0o050)
            self.assertEqual((dest / 'etc/cerebro/config.json').stat().st_mode & 0o040, 0o040)

    def test_existing_inaccessible_service_directory_refused_before_code_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'root'
            dest.mkdir(mode=0o700)
            (dest / 'etc/cerebro').mkdir(parents=True)
            (dest / 'etc').chmod(0o755)
            (dest / 'etc/cerebro').chmod(0o700)
            result = self.run_install('--root', str(dest), '--config',
                                      str(ROOT / 'examples/config.json'), '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('existing service directory requires reviewed permissions', result.stderr)
            self.assertFalse((dest / 'opt').exists())
            self.assertFalse((dest / 'etc/cerebro/config.json').exists())

    def test_incompatible_upgrade_directory_preserves_previous_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'root'
            config = ROOT / 'examples/config.json'
            first = self.run_install('--root', str(dest), '--config', str(config), '--apply')
            self.assertEqual(first.returncode, 0, first.stderr)
            receipt = dest / 'var/lib/cerebro-installer/previous.json'
            before_receipt = receipt.read_bytes()
            target = dest / 'etc/cerebro/config.json'
            before_target = target.read_bytes()
            incompatible = dest / 'etc/cerebro'
            incompatible.chmod(0o700)
            modified = Path(tmp) / 'changed.json'
            payload = json.loads(config.read_text())
            payload['portal']['title'] = 'Next release'
            modified.write_text(json.dumps(payload))
            failed = self.run_install('--root', str(dest), '--config', str(modified), '--apply')
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn('existing service directory requires reviewed permissions', failed.stderr)
            self.assertEqual(target.read_bytes(), before_target)
            self.assertEqual(receipt.read_bytes(), before_receipt)
            self.assertEqual(incompatible.stat().st_mode & 0o777, 0o700)

    def test_installed_module_serves_api_from_isolated_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'root'
            config = str(ROOT/'examples/config.json')
            first = self.run_install('--root', str(dest), '--config', config, '--apply')
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_install('--root', str(dest), '--config', config, '--apply')
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn('changed=0', second.stdout)
            installed = dest/'opt/cerebro'
            script = '''import json, os, sys, threading, urllib.request
from pathlib import Path
from security_portal.config import load_config
from security_portal.server import PortalServer
import security_portal
assert Path(security_portal.__file__).resolve().is_relative_to(Path(os.environ['PYTHONPATH']))
config = load_config(Path(sys.argv[1]))
server = PortalServer(('127.0.0.1', 0), config=config,
                      static_root=Path(security_portal.__file__).parent/'static')
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    base = 'http://127.0.0.1:' + str(server.server_port)
    with urllib.request.urlopen(base+'/api/v1/overview', timeout=5) as response:
        payload = json.load(response)
        assert payload['schema_version'] == 'cerebro.integration.v1'
        assert payload['overview']['integration_count'] == 2
        assert payload['integrations'][0]['state'] == 'unavailable'
    with urllib.request.urlopen(base+'/', timeout=5) as response:
        assert b'Cerebro' in response.read()
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
'''
            result = subprocess.run([sys.executable, '-c', script,
                                     str(dest/'etc/cerebro/config.json')], cwd=tmp,
                                    env={**os.environ, 'PYTHONPATH': str(installed)},
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rollback_restores_existing_config_mode_and_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'root'; target = dest/'etc/cerebro/config.json'
            target.parent.mkdir(parents=True)
            (dest/'etc').chmod(0o755)
            target.parent.chmod(0o750)
            target.write_text('prior configuration')
            target.chmod(0o600)
            original = target.stat()
            config = ROOT/'examples/config.json'
            applied = self.run_install('--root', str(dest), '--config', str(config), '--apply')
            self.assertEqual(applied.returncode, 0, applied.stderr)
            rolled = self.run_install('--root', str(dest), '--rollback', '--apply')
            self.assertEqual(rolled.returncode, 0, rolled.stderr)
            self.assertEqual(target.read_text(), 'prior configuration')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual((target.stat().st_uid, target.stat().st_gid),
                             (original.st_uid, original.st_gid))

    def test_rollback_preflights_all_receipt_owners_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            config = root/'etc/cerebro/config.json'
            unit = root/'etc/systemd/system/cerebro.service'
            state = root/'var/lib/cerebro-installer/previous.json'
            for target in (config, unit, state):
                target.parent.mkdir(parents=True, exist_ok=True)
            config.write_text('current config')
            unit.write_text('current unit')
            receipt = {
                'etc/cerebro/config.json': {'content': 'previous config'.encode().hex(),
                                            'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
                'etc/systemd/system/cerebro.service': {'content': 'previous unit'.encode().hex(),
                                                       'mode': 0o644, 'uid': os.getuid() + 1,
                                                       'gid': os.getgid()},
            }
            state.write_text(json.dumps(receipt))
            state.chmod(0o600)
            result = self.run_install('--root', str(root), '--rollback', '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(config.read_text(), 'current config')
            self.assertEqual(unit.read_text(), 'current unit')
            self.assertTrue(state.exists())

    def test_rollback_rejects_unrepresentable_owner_as_invalid_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            config = root/'etc/cerebro/config.json'
            unit = root/'etc/systemd/system/cerebro.service'
            state = root/'var/lib/cerebro-installer/previous.json'
            for target in (config, unit, state):
                target.parent.mkdir(parents=True, exist_ok=True)
            config.write_text('current config')
            unit.write_text('current unit')
            state.write_text(json.dumps({
                'etc/cerebro/config.json': {'content': 'previous config'.encode().hex(),
                                            'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()},
                'etc/systemd/system/cerebro.service': {'content': 'previous unit'.encode().hex(),
                                                       'mode': 0o644, 'uid': 2**64, 'gid': os.getgid()},
            }))
            state.chmod(0o600)
            result = self.run_install('--root', str(root), '--rollback', '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid rollback metadata', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertEqual(config.read_text(), 'current config')
            self.assertEqual(unit.read_text(), 'current unit')
            self.assertTrue(state.exists())

    def test_rollback_rejects_new_receipt_with_null_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            state = root/'var/lib/cerebro-installer/previous.json'
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({'etc/cerebro/config.json': {
                'content': None, 'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()}}))
            state.chmod(0o600)
            result = self.run_install('--root', str(root), '--rollback', '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid rollback content', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertTrue(state.exists())

    def test_activation_requires_attestation_and_real_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=self.run_install('--root', tmp, '--config', str(ROOT/'examples/config.json'), '--apply', '--activate')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(tmp)/'etc/cerebro/config.json').exists())

    def test_install_refuses_symlink_ancestor_and_preserves_outside(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'; outside=Path(tmp)/'outside'
            root.mkdir(); outside.mkdir()
            (root/'etc').symlink_to(outside, target_is_directory=True)
            result=self.run_install('--root',str(root),'--config',str(ROOT/'examples/config.json'),'--apply')
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((outside/'cerebro').exists())
            self.assertFalse((root/'var').exists())

    def test_install_refuses_writable_ancestor_before_receipt_or_target_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'
            target_dir = root / 'etc'
            target_dir.mkdir(parents=True)
            target_dir.chmod(0o777)
            try:
                result = self.run_install('--root', str(root), '--config',
                                          str(ROOT/'examples/config.json'), '--apply')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsafe installation directory', result.stderr)
                self.assertFalse((root/'etc/cerebro').exists())
                self.assertFalse((root/'var').exists())
            finally:
                target_dir.chmod(0o700)

    def test_rollback_rejects_unexpected_receipt_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'; state=root/'var/lib/cerebro-installer/previous.json'
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({'../outside':'00'}))
            state.chmod(0o600)
            result=self.run_install('--root',str(root),'--rollback','--apply')
            self.assertNotEqual(result.returncode,0)
            self.assertTrue(state.exists())

    def test_rollback_refuses_writable_receipt_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            target = root/'etc/cerebro/config.json'
            state = root/'var/lib/cerebro-installer/previous.json'
            target.parent.mkdir(parents=True)
            state.parent.mkdir(parents=True)
            target.write_text('current config')
            state.write_text(json.dumps({'etc/cerebro/config.json': '7072696f72'}))
            state.chmod(0o666)
            try:
                result = self.run_install('--root', str(root), '--rollback', '--apply')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsafe rollback receipt', result.stderr)
                self.assertEqual(target.read_text(), 'current config')
                self.assertTrue(state.exists())
            finally:
                state.chmod(0o600)
