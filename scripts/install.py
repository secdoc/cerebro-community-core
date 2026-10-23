#!/usr/bin/env python3
"""Conservative Debian 13 single-node package installer; offline root simulation supported."""
import argparse
import fcntl
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
    """Require trusted, non-writable ancestors for privileged target operations."""
    if name.is_absolute() or '..' in name.parts:
        raise ValueError('installation target escapes root')
    target = root / name
    trusted_uid = 0 if root == Path('/') else os.geteuid()
    for ancestor in (root, *(root.joinpath(*name.parts[:index]) for index in range(1, len(name.parts)))):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != trusted_uid or info.st_mode & 0o022:
            raise ValueError('unsafe installation directory ownership, permissions or type')
    try:
        info = target.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('unsafe installation target')
    return target

def safe_receipt(root, state):
    """A rollback recipe must not be editable by an untrusted local user."""
    safe_target(root, Path('var/lib/cerebro-installer/previous.json'))
    try:
        info = state.lstat()
    except FileNotFoundError:
        return
    trusted_uid = 0 if root == Path('/') else os.geteuid()
    if info.st_uid != trusted_uid or info.st_mode & 0o077:
        raise ValueError('unsafe rollback receipt ownership or permissions')


def ensure_service_directories(root, create=True):
    """Create service paths with usable modes despite the installer's 0077 umask.

    Do not loosen pre-existing directories: an operator must review their ownership
    and permissions instead of allowing a package install to rewrite them.
    """
    service_gid = grp.getgrnam('cerebro').gr_gid if root == Path('/') else os.getgid()
    directories = (('opt', 0o755, None), ('opt/cerebro', 0o755, None),
                   ('opt/cerebro/security_portal', 0o755, None),
                   ('opt/cerebro/security_portal/static', 0o755, None),
                   ('etc', 0o755, None), ('etc/cerebro', 0o750, service_gid),
                   ('etc/systemd', 0o755, None),
                   ('etc/systemd/system', 0o755, None))
    for name, mode, group in directories:
        path = root / name
        safe_target(root, Path(name) / '.cerebro-directory-check')
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        expected_uid = 0 if root == Path('/') else os.geteuid()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                or info.st_mode & mode != mode or info.st_mode & 0o022
                or (group is not None and info.st_gid != group)):
            raise ValueError('existing service directory requires reviewed permissions: ' + name)
    if not create:
        return
    for name, mode, group in directories:
        path = root / name
        if path.exists():
            continue
        path.mkdir(mode=mode)
        os.chmod(path, mode)
        if group is not None:
            os.chown(path, 0 if root == Path('/') else os.geteuid(), group)


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
    safe_target(state.parents[3], Path('var/lib/cerebro-installer/previous.json'))
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

def finish_rollback(state, dest):
    """Retain the recovery receipt until systemd has accepted restored unit files."""
    if dest == Path('/'):
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    state.unlink()

def finish_apply(state, receipt, dest):
    """A failed reload must leave a pending receipt and block a later apply."""
    if dest == Path('/'):
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    save_receipt(state, {'_format': 1, 'status': 'complete', 'targets': receipt})

def installer_lock(root):
    """Serialize all mutating installer transactions, including rollback."""
    name = Path('run/cerebro-installer.lock') if root == Path('/') else Path('.cerebro-installer.lock')
    if root != Path('/') and not root.exists():
        root.mkdir(mode=0o700)
    target = safe_target(root, name)
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        info = os.fstat(fd)
        expected_uid = 0 if root == Path('/') else os.geteuid()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o077:
            raise ValueError('unsafe installer lock ownership, permissions or type')
        fcntl.flock(fd, fcntl.LOCK_EX)
        # The lock name must still identify the descriptor after waiting.
        current = target.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('installer lock replaced while waiting')
        return fd
    except BaseException:
        os.close(fd)
        raise


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
    if args.apply:
        lock_fd = installer_lock(args.root)
        try:
            return run_transaction(args, parser)
        finally:
            os.close(lock_fd)
    return run_transaction(args, parser)

def run_transaction(args, parser):
    dest=args.root
    if args.apply:
        os.umask(0o077)
    state=dest/'var/lib/cerebro-installer/previous.json'
    safe_receipt(dest, state)
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
                safe_target(dest, Path(name))
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
        finish_rollback(state, dest)
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
    # Validate existing directory metadata before replacing a recovery point.
    ensure_service_directories(dest, create=False)
    if dest == Path('/'):
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
    ensure_service_directories(dest)
    for name,data in changes.items():
        target=dest/name; target.parent.mkdir(parents=True,exist_ok=True)
        safe_target(dest, Path(name))
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
        finish_apply(state, receipt, dest)
    if dest == Path('/'):
        if not changes:
            subprocess.run(['systemctl','daemon-reload'],check=True)
        if args.activate:
            subprocess.run(['systemctl','enable','--now','cerebro.service'],check=True)
            subprocess.run(['systemctl','is-active','--quiet','cerebro.service'],check=True)
    print('installed=complete activation=' + ('enabled' if args.activate else 'disabled'))


if __name__=='__main__':
    try: main()
    except (ConfigError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'installer error: {exc}',file=sys.stderr); sys.exit(1)
