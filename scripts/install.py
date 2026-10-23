#!/usr/bin/env python3
"""Conservative Debian 13 single-node package installer; offline root simulation supported."""
import argparse
import json
import os
import grp
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

import urllib.error
import urllib.request
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_portal.config import load_config, ConfigError

FILES = {'security_portal/__init__.py', 'security_portal/config.py', 'security_portal/connectors.py',
         'security_portal/model.py', 'security_portal/server.py', 'security_portal/static/index.html',
         'security_portal/static/app.js', 'security_portal/static/styles.css'}
UNIT = '''[Unit]
Description=Cerebro read-only portal (requires authenticated TLS proxy)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=cerebro
Group=cerebro
WorkingDirectory=/opt/cerebro
ExecStart=/usr/bin/python3 -m security_portal.server --config /etc/cerebro/config.json --bind 127.0.0.1 --port 8080
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def unit_files(config):
    files = {Path('opt/cerebro') / name: (ROOT/name).read_bytes() for name in FILES}
    files[Path('etc/cerebro/config.json')] = json.dumps(config, indent=2, sort_keys=True).encode() + b'\n'
    files[Path('etc/systemd/system/cerebro.service')] = UNIT.encode()
    return files

def safe_target(root, name):
    """Refuse symlinks and non-regular targets before a privileged file write."""
    if name.is_absolute() or '..' in name.parts:
        raise ValueError('installation target escapes root')
    target = root / name
    for ancestor in (root, *reversed(target.parents[:-1])):
        if ancestor.is_symlink():
            raise ValueError('symlink in installation path')
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError('unsafe installation target')
    return target


def gate_check(url):
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('proxy check requires a credential-free HTTPS URL')
    class RefuseRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    opener = urllib.request.build_opener(RefuseRedirect())
    try:
        opener.open(urllib.request.Request(url, method='GET'), timeout=8)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403): return
        raise ValueError('unauthenticated proxy probe must return 401 or 403') from exc
    raise ValueError('unauthenticated proxy probe did not deny access')

def save_receipt(state, payload):
    """Commit a durable receipt before target mutation or phase transition."""
    state.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=state.parent, prefix='.cerebro-receipt-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, state)
        directory = os.open(state.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def main():
    parser=argparse.ArgumentParser(description='Cerebro Debian 13 installer; dry-run by default')
    parser.add_argument('--root', type=Path, default=Path('/'), help='isolated simulation root, never activates')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--gate-verified', action='store_true', help='operator attests TLS identity policy and authorization tested')
    parser.add_argument('--proxy-check-url', help='unauthenticated HTTPS URL to probe for 401/403')
    args=parser.parse_args()
    if args.activate and (args.root != Path('/') or not args.apply or not args.gate_verified or not args.proxy_check_url or args.rollback):
        parser.error('activation requires live root, --apply, --gate-verified and --proxy-check-url')
    if args.apply and args.dry_run: parser.error('choose apply or dry-run')
    if args.root == Path('/') and args.apply:
        if os.geteuid() != 0: parser.error('live installation requires root')
        if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text() and 'VERSION_ID=13' not in Path('/etc/os-release').read_text():
            parser.error('live installation is supported only on Debian 13')
        if 'ID=debian' not in Path('/etc/os-release').read_text(): parser.error('Debian required')
    if args.root != Path('/') and (not args.root.is_absolute() or args.root.is_symlink()): parser.error('simulation root must be absolute and not a symlink')
    dest=args.root
    state=dest/'var/lib/cerebro-installer/previous.json'
    safe_target(dest, Path('var/lib/cerebro-installer/previous.json'))
    if args.rollback:
        if not state.is_file(): parser.error('no rollback receipt')
        receipt=json.loads(state.read_text())
        if isinstance(receipt, dict) and receipt.get('_format') == 1:
            if receipt.get('status') not in ('pending', 'complete'):
                raise ValueError('invalid rollback receipt phase')
            receipt = receipt.get('targets')
        if not isinstance(receipt, dict) or not set(receipt).issubset({str(n) for n in unit_files({'portal': {}, 'integrations': []})}):
            raise ValueError('rollback receipt contains unexpected targets')
        for name, previous in receipt.items():
            safe_target(dest, Path(name))
            if isinstance(previous, dict):
                if set(previous) != {'content', 'mode', 'uid', 'gid'} or not isinstance(previous['mode'], int) or isinstance(previous['mode'], bool) or not 0 <= previous['mode'] <= 0o7777 or any(not isinstance(previous[key], int) or isinstance(previous[key], bool) or not 0 <= previous[key] < 2**32 - 1 for key in ('uid', 'gid')):
                    raise ValueError('invalid rollback metadata')
                if dest != Path('/') and (previous['uid'], previous['gid']) != (os.getuid(), os.getgid()):
                    raise ValueError('simulation cannot restore a different file owner')
                if not isinstance(previous['content'], str):
                    raise ValueError('invalid rollback content')
                previous = previous['content']
            if previous is not None and (not isinstance(previous, str) or len(previous) % 2):
                raise ValueError('invalid rollback content')
            if previous is not None:
                bytes.fromhex(previous)
        print('rollback files=' + str(len(receipt)))
        if not args.apply: return
        if dest == Path('/'):
            subprocess.run(['systemctl','disable','--now','cerebro.service'],check=True)
        for name, previous in receipt.items():
            target=safe_target(dest, Path(name))
            if previous is None: target.unlink(missing_ok=True)
            else:
                metadata = previous if isinstance(previous, dict) else None
                content = cast(str, previous['content'] if metadata else previous)
                target.parent.mkdir(parents=True,exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=target.parent, prefix='.cerebro-rollback-')
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(bytes.fromhex(content))
                        stream.flush()
                        os.fsync(stream.fileno())
                    if metadata:
                        os.chmod(tmp, metadata['mode'])
                        if dest == Path('/'):
                            os.chown(tmp, metadata['uid'], metadata['gid'])
                    os.replace(tmp, target)
                finally:
                    if os.path.exists(tmp): os.unlink(tmp)
        state.unlink()
        if dest == Path('/'): subprocess.run(['systemctl','daemon-reload'],check=True)
        print('rollback=complete')
        return
    if args.config is None:
        if not sys.stdin.isatty(): parser.error('--config required in non-interactive mode')
        args.config=Path(input('Absolute path to your reviewed Cerebro JSON config: ').strip())
    config=load_config(args.config)
    files=unit_files(config)
    for name in files:
        safe_target(dest, name)
    changes={str(name): data for name,data in files.items() if not (dest/name).is_file() or (dest/name).read_bytes()!=data}
    print(f'validated integrations={len(config["integrations"])} changed={len(changes)} mode={"apply" if args.apply else "dry-run"}')
    for name in sorted(changes): print('  '+name)
    if not args.apply: return
    if args.activate: gate_check(args.proxy_check_url)
    if state.exists():
        existing = json.loads(state.read_text())
        if isinstance(existing, dict) and existing.get('_format') == 1 and existing.get('status') == 'pending':
            raise ValueError('interrupted installation: run --rollback --apply before retrying')
        if isinstance(existing, dict) and existing.get('_format') == 1 and existing.get('status') != 'complete':
            raise ValueError('invalid existing receipt phase')
    if dest == Path('/'):
        try: pwd.getpwnam('cerebro')
        except KeyError:
            subprocess.run(['useradd','--system','--user-group','--home','/nonexistent','--shell','/usr/sbin/nologin','cerebro'],check=True)
        subprocess.run(['systemctl','disable','--now','cerebro.service'],check=False)
    receipt={}
    for name in changes:
        target = dest/name
        if target.exists():
            original = target.stat()
            receipt[name] = {'content': target.read_bytes().hex(), 'mode': stat.S_IMODE(original.st_mode),
                             'uid': original.st_uid, 'gid': original.st_gid}
        else:
            receipt[name] = None
    if changes:
        save_receipt(state, {'_format': 1, 'status': 'pending', 'targets': receipt})
    for name,data in changes.items():
        target=dest/name; target.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(dir=target.parent, prefix='.cerebro-')
        try:
            with os.fdopen(fd,'wb') as stream: stream.write(data)
            os.chmod(tmp,0o640 if name=='etc/cerebro/config.json' else 0o644)
            if dest == Path('/') and name == 'etc/cerebro/config.json':
                os.chown(tmp,0,grp.getgrnam('cerebro').gr_gid)
            os.replace(tmp,target)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    if changes:
        save_receipt(state, {'_format': 1, 'status': 'complete', 'targets': receipt})
    if dest == Path('/'):
        subprocess.run(['systemctl','daemon-reload'],check=True)
        if args.activate:
            subprocess.run(['systemctl','enable','--now','cerebro.service'],check=True)
            subprocess.run(['systemctl','is-active','--quiet','cerebro.service'],check=True)
    print('installed=complete activation=' + ('enabled' if args.activate else 'disabled'))


if __name__=='__main__':
    try: main()
    except (ConfigError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'installer error: {exc}',file=sys.stderr); sys.exit(1)
