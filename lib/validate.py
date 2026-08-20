#!/usr/bin/env python3
from pathlib import Path
import sys,tomllib,json
S={"ubuntu-24.04","ubuntu-26.04","debian-12","debian-13","kali-rolling","parrot-7"}
def v(root,m):
 e=[]; p=root/'modules'/m/'module.toml'
 try:d=tomllib.loads(p.read_text())
 except Exception as x:return [str(x)]
 t=p.parent/'template'
 for f in ('AGENTS.md','opencode.json','start.sh'):
  if not (t/f).exists():e.append('missing template/'+f)
 try:j=json.loads((t/'opencode.json').read_text());
 except Exception as x:e.append('bad opencode.json '+str(x));j={}
 if j.get('subagent_depth')!=1:e.append('subagent_depth must be 1')
 if j.get('permission',{}).get('external_directory')!='deny':e.append('external_directory must be deny')
 if set(d.get('platforms',{}).get('supported',[]))!=S:e.append('platform set mismatch')
 c=tomllib.loads((root/'dependencies/catalog.toml').read_text())['dependencies']
 for x in d.get('dependencies',{}).get('required',[])+d.get('dependencies',{}).get('optional',[]):
  if x not in c:e.append('unknown dependency '+x)
  if any(y in x.lower() for y in ('qemu','docker','emulator','firmae')):e.append('forbidden emulation dependency '+x)
 return e
root=Path(sys.argv[2]); mods=[sys.argv[3]] if sys.argv[1]=='module' else [x.parent.name for x in (root/'modules').glob('*/module.toml')]; bad=[]
for m in sorted(mods):
 e=v(root,m);print(('✓' if not e else '✗'),m);bad+=e
 for x in e:print('  ',x)
if bad:raise SystemExit(1)
