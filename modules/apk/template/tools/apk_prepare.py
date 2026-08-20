#!/usr/bin/env python3
import hashlib,subprocess,tomllib,shutil,os
from pathlib import Path
R=Path(__file__).resolve().parents[1]
with (R/'target/TARGET.toml').open('rb') as f:c=tomllib.load(f)
if not c.get('engagement',{}).get('authorized',False):raise SystemExit('authorized=false')
p=(R/c['apk']['path']).resolve();p.relative_to(R.resolve())
if not p.is_file():raise SystemExit('APK missing: '+str(p))
for d in ['work/tmp','extracted/jadx','extracted/apktool','reports/tool-output']:(R/d).mkdir(parents=True,exist_ok=True)
env=os.environ|{'TMPDIR':str(R/'work/tmp'),'TMP':str(R/'work/tmp'),'TEMP':str(R/'work/tmp')}
(R/'reports/tool-output/apk.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'\n')
def run(cmd,name):
 if not shutil.which(cmd[0]):return
 q=subprocess.run(cmd,cwd=R,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(R/'reports/tool-output'/name).write_text(q.stdout)
run(['file',str(p)],'file.txt');run(['apksigner','verify','--verbose','--print-certs',str(p)],'apksigner.txt');run(['aapt','dump','badging',str(p)],'aapt.txt');run(['jadx','-d',str(R/'extracted/jadx'),str(p)],'jadx.txt');run(['apktool','d','-f','-o',str(R/'extracted/apktool'),str(p)],'apktool.txt')
print('prepared',p)
