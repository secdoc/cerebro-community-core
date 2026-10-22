#!/usr/bin/env python3
"""Interactive, credential-free feed mapping generator. No install side effects."""
import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_portal.config import load_config, ConfigError


def ask(label, default=''):
    value=input(f'{label}' + (f' [{default}]' if default else '') + ': ').strip()
    return value or default


def main():
    parser=argparse.ArgumentParser(description='Interactive Cerebro source mapping wizard')
    parser.add_argument('--output',type=Path,required=True,help='private adopter-owned config path, outside this checkout')
    parser.add_argument('--apply',action='store_true',help='save validated config (dry-run by default)')
    args=parser.parse_args()
    if args.output.exists(): parser.error('output already exists; refuse overwrite')
    if ROOT == args.output or ROOT in args.output.resolve().parents: parser.error('keep adopter config outside public checkout')
    if not args.output.is_absolute(): parser.error('output must be absolute')
    print('Cerebro read-only mapping wizard. No credentials or private values are echoed to output.')
    title=ask('Portal title','Cerebro')
    integrations=[]
    while True:
        name=ask('Feed display name (blank to finish)')
        if not name: break
        ident=ask('Unique feed ID (letters, digits, hyphen)')
        if not ident.replace('-','').isalnum() or not ident:
            raise ValueError('invalid feed ID')
        category=ask('Category','SOC')
        kind=ask('Source type: file or https','file')
        spec={'id':ident,'name':name,'category':category,'connector':'json_file' if kind=='file' else 'http_json',
              'max_age_seconds':int(ask('Maximum snapshot age in seconds','600'))}
        if kind=='file': spec['path']=ask('Absolute local JSON path')
        elif kind=='https':
            spec['url']=ask('Exact HTTPS JSON GET URL')
            spec['allowed_origins']=[ask('Exact allowed HTTPS origin (scheme, host, port if needed)')]
            spec['method']='GET'
        else: raise ValueError('source type must be file or https')
        spec['collected_at_path']=ask('Timestamp dotted path','collected_at')
        spec['healthy_path']=ask('Boolean health dotted path','healthy')
        paths={}
        while True:
            label=ask('Scalar summary label (blank to finish this feed)')
            if not label: break
            paths[label]=ask('Source dotted path for '+label)
        spec['summary_paths']=paths
        integrations.append(spec)
    config={'portal':{'title':title,'classification':'Internal','refresh_seconds':60},'integrations':integrations}
    with tempfile.TemporaryDirectory() as scratch:
        candidate=Path(scratch)/'config.json'; candidate.write_text(json.dumps(config))
        load_config(candidate)
    print(f'validated feeds={len(integrations)} mode={"apply" if args.apply else "dry-run"}; no feed requests made')
    if args.apply:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream: json.dump(config,stream,indent=2);stream.write('\n')
        print('saved adopter configuration (mode 0600)')


if __name__=='__main__':
    try: main()
    except (EOFError, ValueError, ConfigError, OSError) as exc:
        print(f'wizard error: {exc}',file=sys.stderr);sys.exit(1)
