#!/usr/bin/env python3
import json,os,signal,subprocess,time
from pathlib import Path
root=Path.home()/'bench-ouro-startup'
rows=[]
for line in subprocess.check_output(['ps','-u',str(os.getuid()),'-o','pid=,ppid=,pgid=,command='],text=True).splitlines():
 parts=line.split(None,3)
 if len(parts)==4:rows.append((int(parts[0]),int(parts[1]),int(parts[2]),parts[3]))
parents=[r[0] for r in rows if r[3].startswith('python3 '+str(root/'harness/suite_paired.py')+' ') and '--root '+str(root/'runs/perf-after')+' ' in r[3]]
owned=set(parents)
for pid in parents:
 try:os.kill(pid,signal.SIGSTOP)
 except ProcessLookupError:pass
while True:
 extra={pid for pid,ppid,_,_ in rows if ppid in owned}-owned
 if not extra:break
 owned|=extra
for pid,_,group,_ in reversed(rows):
 if pid not in owned:continue
 try:
  if group==pid:os.killpg(group,signal.SIGTERM)
  else:os.kill(pid,signal.SIGTERM)
  if pid in parents:os.kill(pid,signal.SIGCONT)
 except ProcessLookupError:pass
(root/'results/perf-candidate-interruption.json').write_text(json.dumps({'reason':'Initial candidate retains cached version evidence; restore fresh readback before final score','owned_pids_signaled':sorted(owned),'excluded_from_final_score':True},indent=2)+'\n')
print('Stopped only initial candidate performance processes:',sorted(owned))
