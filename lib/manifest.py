#!/usr/bin/env python3
from pathlib import Path
import sys,tomllib
cmd=sys.argv[1]
def load(p):
 with open(p,'rb') as f:return tomllib.load(f)
if cmd=='list':
 rows=[]
 for p in sorted(Path(sys.argv[2]).glob('*/module.toml')):
  m=load(p)['module']; rows.append((m['id'],m.get('description','')))
 print('MODULE    DESCRIPTION')
 for a,b in rows: print(f'{a:<9} {b}')
elif cmd=='deps':
 d=load(sys.argv[2]).get('dependencies',{}); which=sys.argv[3]; vals=[]
 if which in ('required','all'): vals+=d.get('required',[])
 if which in ('optional','all'): vals+=d.get('optional',[])
 for x in dict.fromkeys(vals): print(x)
