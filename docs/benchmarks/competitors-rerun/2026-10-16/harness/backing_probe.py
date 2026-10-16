#!/usr/bin/env python3
"""Prove native workspace writes reach the host, independently of timing."""
import argparse,json,os,uuid
from pathlib import Path
from suite import Suite

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if (a.out/'backing.json').exists():raise SystemExit('Evidence exists')
 s=Suite(a.root,a.out,0,0,['direct','ouro-jail','greywall','mxc'])
 rows=[]
 try:
  (a.out/'metadata.json').write_text(json.dumps(s.metadata(),indent=2)+'\n')
  payload=s.work/'backing_payload.py'
  payload.write_text("import pathlib,os,json,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);v=p.stat();print(json.dumps({'probe':'backing','dev':v.st_dev,'ino':v.st_ino,'bytes':v.st_size}))\n")
  for tool in s.tools:
   name='backing-'+tool+'.txt';nonce=uuid.uuid4().hex
   r=s.run(tool,[s.python,str(payload),name,nonce],'backing','shared-workspace')
   file=s.work/name;st=file.stat() if file.exists() else None
   child=r['records'][0] if len(r['records'])==1 else {}
   rows.append({'tool':tool,'exit':r['exit'],'host_nonce_matches':bool(st and file.read_text()==nonce),'same_inode':bool(st and child.get('ino')==st.st_ino and child.get('dev')==st.st_dev),'child':child,'host':{'dev':st.st_dev,'ino':st.st_ino,'bytes':st.st_size} if st else None,'sequence':r['sequence']})
  (a.out/'backing.json').write_text(json.dumps(rows,indent=2)+'\n')
 finally:s.close()
 print(json.dumps(rows))
if __name__=='__main__':main()
