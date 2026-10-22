#!/usr/bin/env python3
"""Scan every candidate file for common private bindings; heuristic, not proof."""
import ipaddress
import os
import re
import sys
from pathlib import Path

SKIP={'.git','__pycache__','.venv','node_modules'}
DNS=re.compile(r'\b(?:[a-z0-9-]+\.)+(?:home|internal|lan)\b',re.I)
IP=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6=re.compile(r'(?<![A-Za-z0-9_.:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9_.:])')
SECRET=re.compile(r'(?i)\b(?:password|api[_-]?key|token|secret)\s*[:=]\s*[\x22\x27]?[A-Za-z0-9_-]{12,}')
KEY=re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
PATH=re.compile(r'/(' + r'home/[^ /\x22\x27]+|opt/data/' + r'home/[^ /\x22\x27]+)')

def scan(root):
    findings=[]
    for directory,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in SKIP]
        for name in files:
            path=Path(directory)/name
            if name in SKIP: continue
            text=path.read_bytes().decode('utf-8','ignore')
            for pattern,label in ((DNS,'private DNS'),(SECRET,'secret assignment'),(KEY,'private key'),(PATH,'operator path')):
                if pattern.search(text): findings.append((str(path.relative_to(root)),label))
            for candidate in IP.findall(text):
                address=ipaddress.ip_address(candidate)
                if address.is_private and not address.is_loopback and not any(address in net for net in (
                    ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
                    ipaddress.ip_network('203.0.113.0/24'))):
                    findings.append((str(path.relative_to(root)),'private IP'))
            for candidate in IPV6.findall(text):
                try:
                    address=ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if address.is_private and not address.is_loopback and address not in ipaddress.ip_network('2001:db8::/32'):
                    findings.append((str(path.relative_to(root)), 'private IPv6'))
    return findings

if __name__=='__main__':
    hits=scan(Path(sys.argv[1] if len(sys.argv)>1 else '.'))
    for path,label in hits: print(path,label)
    print(f'scrub findings={len(hits)}')
    sys.exit(bool(hits))
