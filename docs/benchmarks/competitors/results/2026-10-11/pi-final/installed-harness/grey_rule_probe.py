#!/usr/bin/env python3
"""Test documented denyRead precedence and a minimal RO-parent configuration."""
import argparse,json
from pathlib import Path
from suite import Suite
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if (a.out/'rules.json').exists():raise SystemExit('Evidence exists')
 s=Suite(a.root,a.out,0,0,['greywall']);rows=[]
 try:
  (a.out/'metadata.json').write_text(json.dumps(s.metadata(),indent=2)+'\n')
  base=json.loads(s.grey_config.read_text())
  for variant in ['deny-write-parent','readonly-parent-only']:
   cfg=json.loads(json.dumps(base))
   if variant=='readonly-parent-only':cfg['filesystem']['denyWrite']=[]
   s.grey_config.write_text(json.dumps(cfg,indent=2)+'\n')
   (a.out/(variant+'.json')).write_text(s.grey_config.read_text())
   for name,args in [('private-read',['read',str(s.secret)]),('symlink-read',['read',str(s.work/'read-link')]),('readonly-write',['write',str(s.readonly)])]:
    s.readonly.write_bytes(b'original')
    r=s.run('greywall',[s.python,str(s.payload),'probe',*args],'rule-probe',variant+'/'+name)
    rows.append({'variant':variant,'probe':name,'exit':r['exit'],'records':r['records'],'host_readonly_mutated':s.readonly.read_bytes()!=b'original','sequence':r['sequence']})
  (a.out/'rules.json').write_text(json.dumps(rows,indent=2)+'\n')
 finally:s.close()
 print(json.dumps(rows))
if __name__=='__main__':main()
