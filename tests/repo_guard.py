#!/usr/bin/env python3
from pathlib import Path
import sys,re
r=Path(sys.argv[1]); bad=[]
for p in r.rglob('*'):
    if not p.is_file(): continue
    s=str(p.relative_to(r))
    if re.search(r'(?i)\.(apk|aab|apks|bin|img|fw|trx|pcap|pcapng|har)$',s) or s.endswith('/TARGET.toml') or s == 'TARGET.toml':
        bad.append(s)
if bad:
    print('[!] Project/assessment data found in toolkit repository:')
    print('\n'.join(bad))
    raise SystemExit(1)
print('[+] repo-guard clean')
