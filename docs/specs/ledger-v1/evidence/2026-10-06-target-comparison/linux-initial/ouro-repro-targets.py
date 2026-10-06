from pathlib import Path
import subprocess,os,json,time,socket,shutil
root=Path('/home/ubuntu/ouro-targets-repro-20261006')
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
        runs=[]
        for name in ['target-left','target-right']:
            args=['run','--request-id',name,'--jail-bin',str(root/'ouro-jail'),'--workspace',str(root/'workspace'),'--jail','tool','--limit','wall=10s','--io','batch','--json','--','/bin/sh','-c','printf x > '+name]
            output=subprocess.run(cli+args,env=env,capture_output=True,text=True,timeout=30)
            assert output.returncode==0,output.stderr
            run=json.loads(output.stdout);runs.append(run['run_id'])
            stream=root/'data/ledger'/run['run_id']/'events-0001.ndjson'
            for line in stream.read_text().splitlines():
                record=json.loads(line)
                if record.get('operation') in ['fs.write','fs.create']:
                    print(name,record['seq'],record['operation'],record['fields'],flush=True)
        output=subprocess.run(cli+['diff',*runs,'--by','targets','--json'],env=env,capture_output=True,text=True,timeout=30)
        (root/'diff.json').write_text(output.stdout)
        report=json.loads(output.stdout)
        print('classification',report['classes']['fs.write'],flush=True)
        print('missing',report['left']['unavailable_targets'],flush=True)
    finally:writer.terminate();writer.wait(timeout=10)
