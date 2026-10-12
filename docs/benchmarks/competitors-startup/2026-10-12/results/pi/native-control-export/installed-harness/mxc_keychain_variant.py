#!/usr/bin/env python3
"""Explicit documented Seatbelt keychainAccess compatibility variant."""
import json,sys
from pathlib import Path
import agentbench_v2 as bench
original=bench.command
def command(*args,**kwargs):
 argv,env,cfg=original(*args,**kwargs)
 if cfg and cfg.get('containment')=='seatbelt':
  cfg.setdefault('seatbelt',{})['keychainAccess']=True
  Path(argv[1]).write_text(json.dumps(cfg))
  bench.write(Path(argv[1]).parent/'config/mxc-keychain.json',cfg,args[-1] if isinstance(args[-1],str) else '')
 return argv,env,cfg
bench.command=command
if __name__=='__main__':bench.main()
