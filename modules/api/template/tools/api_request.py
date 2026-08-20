#!/usr/bin/env python3
import argparse,json,time,tomllib,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CFG=ROOT/'target/TARGET.toml';LOG=ROOT/'reports/http'
def die(x):raise SystemExit(x)
def cfg():
 with CFG.open('rb') as f:return tomllib.load(f)
def rule(c,u,m):
 hits=[x for x in c.get('scope',{}).get('rules',[]) if u.startswith(x['base_url']) and m in [y.upper() for y in x.get('methods',[])]]
 if not hits:die(f'OUT OF SCOPE or method denied: {m} {u}')
 return max(hits,key=lambda x:len(x['base_url']))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def main():
 a=argparse.ArgumentParser();a.add_argument('method',nargs='?');a.add_argument('url',nargs='?');a.add_argument('--profile',default='anonymous');a.add_argument('--data');a.add_argument('--check',action='store_true');x=a.parse_args();c=cfg()
 if x.check:print('authorized=',c.get('engagement',{}).get('authorized',False));print('rules=',len(c.get('scope',{}).get('rules',[])));return
 if not c.get('engagement',{}).get('authorized',False):die('engagement.authorized=false')
 if not x.method or not x.url:die('method and url required')
 m=x.method.upper();r=rule(c,x.url,m);p=next((q for q in c.get('credentials',{}).get('profiles',[]) if q.get('name')==x.profile),{'headers':{}})
 req=urllib.request.Request(x.url,data=x.data.encode() if x.data else None,headers=p.get('headers',{}),method=m);timeout=c.get('limits',{}).get('request_timeout_seconds',20);time.sleep(c.get('limits',{}).get('request_spacing_ms',500)/1000);opener=urllib.request.build_opener(NoRedirect)
 try:res=opener.open(req,timeout=timeout);status=res.status;body=res.read();location=res.headers.get('Location')
 except urllib.error.HTTPError as e:status=e.code;body=e.read();location=e.headers.get('Location')
 LOG.mkdir(parents=True,exist_ok=True);stamp=str(time.time_ns());(LOG/f'{stamp}.body').write_bytes(body);(LOG/f'{stamp}.json').write_text(json.dumps({'method':m,'url':x.url,'status':status,'location':location,'scope':r['base_url'],'profile':x.profile},indent=2));print('HTTP',status);print('Location',location or '-');print(body[:12000].decode(errors='replace'))
if __name__=='__main__':main()
