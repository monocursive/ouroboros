#!/usr/bin/env python3
"""Public host and executable provenance; never reads credential files."""
import argparse,hashlib,json,os,platform,shutil,subprocess,time
from pathlib import Path
def run(argv):
 try:
  p=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
  return {'exit':p.returncode,'output':p.stdout}
 except (OSError,subprocess.TimeoutExpired) as e:return {'error':str(e)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args()
 facts={'date_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'host':platform.uname()._asdict(),'cpu_count':os.cpu_count(),'bin_hashes':{},'commands':{}}
 for base in ['bin','linux-bin']:
  if not (a.root/base).exists():continue
  for path in sorted((a.root/base).iterdir()):
   if path.is_file():facts['bin_hashes'][str(path.relative_to(a.root))]=hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
 cmds={'disk':['df','-h',str(a.root)],'identity':['id'],'python':['python3','--version'],'docker-info':['docker','info','--format','{"version":{{json .ServerVersion}},"cpu":{{json .NCPU}},"memory":{{json .MemTotal}},"kernel":{{json .KernelVersion}},"memory_limit":{{json .MemLimit}},"swap_limit":{{json .SwapLimit}},"cpu_quota":{{json .CPUCfsQuota}},"pids_limit":{{json .PidsLimit}},"driver":{{json .Driver}}}'],'openshell-status':['openshell','status']}
 if platform.system()=='Linux':
  cmds.update({'kernel':['uname','-a'],'bwrap':['bwrap','--version'],'apparmor-userns':['sysctl','kernel.apparmor_restrict_unprivileged_userns']})
  for name in ['cpuinfo','meminfo']:
   facts[name]='\n'.join(line for line in (Path('/proc')/name).read_text().splitlines() if not line.startswith('Serial'))+'\n'
  facts['cgroup_controllers']=Path('/sys/fs/cgroup/cgroup.controllers').read_text()
 else:cmds.update({'os':['sw_vers'],'hardware':['sysctl','hw.model','hw.memsize','hw.ncpu','machdep.cpu.brand_string']})
 for name,cmd in cmds.items():facts['commands'][name]=run(cmd)
 (a.root/'results/host-provenance-final.json').write_text(json.dumps(facts,indent=2)+'\n')
 print('Host provenance saved')
if __name__=='__main__':main()
