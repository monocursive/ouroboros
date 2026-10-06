from pathlib import Path
import subprocess,os,json,time,socket,shutil
root=Path('/home/ubuntu/ouro-discovery-repro-20261006')
root.mkdir(mode=0o700)
for d in ['data','config','workspace','config/launch']: (root/d).mkdir(mode=0o700)
profile=root/'config/launch/fixture-discovery.toml'
profile.write_text('name = "fixture-discovery"\njail = "tool"\n');profile.chmod(0o600)
binroot=Path('/home/ubuntu/ouro-ledger-storage-20261004-r1/target/release')
shutil.copyfile(binroot/'ouro-jail',root/'ouro-jail');(root/'ouro-jail').chmod(0o700)
env=dict(os.environ,OURO_CONFIG_DIR=str(root/'config'))
cli=[str(binroot/'ouro-ledger'),'--data-dir',str(root/'data')]
with (root/'serve.log').open('wb') as log:
    writer=subprocess.Popen(cli+['serve'],env=env,stdout=log,stderr=log)
    try:
        for _ in range(100):
            try:
                with socket.socket(socket.AF_UNIX) as s:s.connect(str(root/'data/ledger/serve.sock'))
                break
            except OSError:time.sleep(.02)
        args=['run','--request-id','discovery-labelled','--jail-bin',str(root/'ouro-jail'),'--workspace',str(root/'workspace'),'--jail','tool','--limit','wall=10s','--io','batch','--capture','stderr','--json','--launch','fixture-discovery','--tag','qa','--tag','blue','--','/bin/sh','-c','printf x >> discovery-executions']
        for name,runargs in [('first',args),('replay',args),('none',['run','--request-id','discovery-other','--jail-bin',str(root/'ouro-jail'),'--workspace',str(root/'workspace'),'--jail','none','--limit','wall=10s','--io','batch','--capture','stderr','--json','--tag','green','--','/bin/true'])]:
            output=subprocess.run(cli+runargs,env=env,capture_output=True,text=True,timeout=30)
            (root/(name+'.stdout')).write_text(output.stdout);(root/(name+'.stderr')).write_text(output.stderr)
            print(name,output.returncode,output.stderr,flush=True)
        for p in (root/'data').rglob('stderr.bin'):print(str(p),p.read_text(),flush=True)
    finally:writer.terminate();writer.wait(timeout=10)
