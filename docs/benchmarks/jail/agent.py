#!/usr/bin/env python3
"""A01 and learning with an installed OpenCode and an empty disposable project.

Uses the credential-free opencode/big-pickle model.
The public price was checked at https://opencode.ai/docs/zen/ on 2026-09-28.
No repository source or operator credentials are placed in the project.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import tomllib

parser=argparse.ArgumentParser()
parser.add_argument('--binary',type=pathlib.Path,required=True)
parser.add_argument('--agent',type=pathlib.Path,required=True)
parser.add_argument('--out',type=pathlib.Path,required=True)
args=parser.parse_args()
os.umask(0o077)
binary=args.binary.resolve(); agent=args.agent.resolve(); out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
root=pathlib.Path(tempfile.mkdtemp(prefix='.ouro-agent-',dir=pathlib.Path.home()))
try:
    work=root/'work';config=root/'config';work.mkdir();config.mkdir()
    subprocess.run(['git','init','-q',str(work)],check=True)
    env={'PATH':os.environ['PATH'],'HOME':str(pathlib.Path.home()),'XDG_RUNTIME_DIR':os.environ.get('XDG_RUNTIME_DIR',''), 'OURO_CONFIG_DIR':str(config),'OURO_DATA_DIR':str(root/'data')}
    rows=[]
    for verb in ['run','learn']:
        output=work/'greeting.txt'
        output.unlink(missing_ok=True)
        command=[str(binary),verb,'--launch','opencode','--workspace',str(work),'--ro',str(agent.parent),'--limit','wall=90s']
        if verb=='learn': command+=['--out',str(out/'learned.toml')]
        command+=['--',str(agent),'run','--model','opencode/big-pickle','Create greeting.txt containing exactly hello followed by a newline. Do not read any other file or use the network yourself.']
        started=time.monotonic()
        result=subprocess.run(command,env=env,capture_output=True,timeout=120)
        (out/(verb+'-stdout.txt')).write_bytes(result.stdout);(out/(verb+'-stderr.txt')).write_bytes(result.stderr)
        attempt=max((root/'data/attempts').iterdir(),key=lambda p:p.stat().st_mtime_ns)
        for name in ['jail.json','trace.ndjson','policy.json']:
            if (attempt/name).is_file(): shutil.copyfile(attempt/name,out/(verb+'-'+name))
        receipt=json.loads((attempt/'jail.json').read_text())
        row={'verb':verb,'argv':command,'seconds':time.monotonic()-started,'exit':result.returncode,'file':output.read_text() if output.exists() else None,'tree_empty':receipt['lifetime']['tree_empty'],'outcome':receipt['outcome'],'coverage':receipt['coverage']}
        rows.append(row)
        (out/'result.json').write_text(json.dumps({'build':json.loads(subprocess.check_output([str(binary),'version','--json'])),'vendor_version':subprocess.check_output([str(agent),'--version'],text=True).strip(),'rows':rows},indent=2)+'\n')
        assert result.returncode==0 and row['file']=='hello\n' and row['tree_empty'] is True,row
        if verb=='learn':
            proposal=tomllib.loads((out/'learned.toml').read_text())
            assert all(value in proposal['provenance']['evidence'] for value in proposal['read_only']+proposal['network_allow'])
            probe=[str(binary),'run','--profile','agent','--workspace',str(work)]
            for path in proposal['read_only']: probe+=['--ro',path]
            for host in proposal['network_allow']: probe+=['--allow-host',host]
            probe+=['--','/usr/bin/true']
            checked=subprocess.run(probe,env=env,capture_output=True,timeout=30)
            assert checked.returncode==0,checked.stderr.decode(errors='replace')
            attempt=max((root/'data/attempts').iterdir(),key=lambda p:p.stat().st_mtime_ns)
            shutil.copyfile(attempt/'jail.json',out/'proposal-probe-jail.json')
        print(verb, 'PASS',round(row['seconds'],2),'s',flush=True)
finally:
    shutil.rmtree(root)
