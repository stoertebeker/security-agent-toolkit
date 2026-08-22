#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,stat,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; CFG=ROOT/'target'/'TARGET.toml'; OUT=ROOT/'reports'/'tool-output'
URL=re.compile(r'https?://[^\s\'"<>]{4,300}',re.I); DOM=re.compile(r'(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![A-Za-z0-9.-])'); IP=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
CAPS={'process-execution':['CreateProcessA','CreateProcessW','WinExec','ShellExecuteA','ShellExecuteW'],'process-injection':['OpenProcess','VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtCreateThreadEx'],'memory-execution':['VirtualAlloc','VirtualProtect'],'persistence-service':['CreateServiceA','CreateServiceW','StartServiceA','StartServiceW'],'network':['socket','connect','InternetOpenA','InternetOpenW','WinHttpOpen','WinHttpConnect','URLDownloadToFileA','URLDownloadToFileW'],'credential-data':['CredReadA','CredReadW','CryptUnprotectData'],'anti-debug':['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess']}
def fail(m): raise SystemExit('[!] '+m)
def main():
  with CFG.open('rb') as f: cfg=tomllib.load(f)
  if not cfg.get('engagement',{}).get('authorized',False): fail('engagement.authorized=false')
  rel=Path(str(cfg.get('target',{}).get('path','')))
  if rel.is_absolute() or '..' in rel.parts or rel.parts[:1] != ('input',): fail('target.path must stay under input/')
  p=(ROOT/rel).resolve()
  try: st=p.lstat()
  except OSError: fail('target missing')
  if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): fail('target must be regular non-symlink')
  data=p.read_bytes()
  if data[:2]!=b'MZ': fail('not an MZ executable')
  maxs=int(cfg.get('analysis',{}).get('max_strings',20000)); rows=[]
  for m in re.finditer(rb'[\x20-\x7e]{4,}',data):
    rows.append((m.start(),m.group().decode('ascii','replace')))
    if len(rows)>=maxs: break
  text='\n'.join(v for _,v in rows); syms=sorted({name for names in CAPS.values() for name in names if name in text}); cap={k:[x for x in v if x in syms] for k,v in CAPS.items() if any(x in syms for x in v)}
  fileout=subprocess.run(['file','-b',str(p)],text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False).stdout.strip(); hashes={'sha256':hashlib.sha256(data).hexdigest(),'sha1':hashlib.sha1(data).hexdigest(),'md5':hashlib.md5(data).hexdigest()}
  base={'schema_version':1,'target':str(p.relative_to(ROOT)),'hashes':hashes,'file':fileout,'size':len(data),'capability_string_leads':cap,'string_count':len(rows),'limitations':['string/API names are leads, not proof of imports or executed behavior','v0 does not yet parse the full PE import/resource tables','static analysis may miss runtime-decrypted or unpacked behavior']}
  iocs={'urls':sorted(set(URL.findall(text)))[:1000],'domains':sorted(set(DOM.findall(text)))[:1000],'ipv4':sorted(set(IP.findall(text)))[:1000]}
  OUT.mkdir(parents=True,exist_ok=True); (OUT/'pe-baseline.json').write_text(json.dumps(base,indent=2,sort_keys=True)+'\n'); (OUT/'pe-iocs.json').write_text(json.dumps(iocs,indent=2,sort_keys=True)+'\n'); (OUT/'pe-strings.txt').write_text('\n'.join(f'0x{o:x} {v}' for o,v in rows)+'\n',errors='replace'); (OUT/'pe.sha256').write_text(hashes['sha256']+'\n'); (OUT/'pe-file.txt').write_text(fileout+'\n'); print(f'[+] PE baseline complete: strings={len(rows)}'); return 0
if __name__=='__main__': raise SystemExit(main())
