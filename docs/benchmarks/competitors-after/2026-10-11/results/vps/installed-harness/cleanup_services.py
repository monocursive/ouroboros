#!/usr/bin/env python3
"""Stop only the temporary gateway PID and proxy launched for this benchmark."""
import argparse,json,os,signal,subprocess,time
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--gateway-pid',type=int,required=True);a=p.parse_args();rows=[]
 lines=subprocess.check_output(['ps','-u',str(os.getuid()),'-o','pid=,command='],text=True).splitlines()
 for line in lines:
  bits=line.strip().split(None,1)
  if len(bits)!=2:continue
  pid=int(bits[0]);cmd=bits[1]
  kind='gateway' if pid==a.gateway_pid and 'openshell-gateway' in cmd else 'proxy' if cmd.startswith(str(a.root/'bin/greyproxy')+' serve ') else None
  if kind is None:continue
  row={'pid':pid,'kind':kind,'signal':'SIGTERM'}
  try:os.kill(pid,signal.SIGTERM);row['sent']=True
  except ProcessLookupError:row['already_exited']=True
  rows.append(row)
 time.sleep(1)
 for row in rows:
  now=subprocess.run(['ps','-p',str(row['pid']),'-o','stat='],capture_output=True,text=True).stdout.strip()
  row['exited_or_zombie']=not now or now.startswith('Z')
 (a.root/'results/service-cleanup.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(rows))
if __name__=='__main__':main()
