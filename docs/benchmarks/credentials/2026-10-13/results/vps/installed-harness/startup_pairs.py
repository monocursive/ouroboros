#!/usr/bin/env python3
"""Randomized paired old/new binaries with an identical static vault policy."""
import argparse,hashlib,json,os,random,statistics,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--before',type=Path,required=True);p.add_argument('--samples',type=int,default=30);a=p.parse_args();root=a.root.resolve();out=root/'results/startup-pairs';out.mkdir();private=root/'paired-private';private.mkdir(mode=0o700);config=private/'config/launch';config.mkdir(parents=True);source=private/'token';source.write_text('fixture-paired-token');source.chmod(0o600);workspace=root/'paired-work';workspace.mkdir()
    profile='name="probe"\njail="agent"\nhome_is_state=true\n[credentials.api]\nmode="vault"\nsource='+json.dumps(str(source))+'\nhosts=["http://127.0.0.1:54321"]\nallow_plaintext=true\nheader={name="x-api-key"}\n[network]\nallow=["127.0.0.1:54321"]\n';(config/'probe.toml').write_text(profile);(config/'probe.toml').chmod(0o600)
    env=dict(os.environ,OURO_CONFIG_DIR=str(config.parent),OURO_DATA_DIR=str(root/'data'));env.pop('ANTHROPIC_API_KEY',None);rng=random.Random(20261013);rows=[];bins={'before':a.before.resolve(),'after':root/'bin/ouro-jail'}
    for pair in range(-3,a.samples):
        modes=['before','after'];rng.shuffle(modes)
        for mode in modes:
            directory=out/('%02d-%s'%(pair+3,mode));directory.mkdir();argv=[str(bins[mode]),'run','--launch','probe','--workspace',str(workspace),'--limit','wall=20s','--receipt',str(directory/'jail.json'),'--','/bin/true'];start=time.perf_counter_ns();r=subprocess.run(argv,env=env,capture_output=True,timeout=50)
            row={'pair':pair,'warmup':pair<0,'mode':mode,'exit':r.returncode,'elapsed_ms':(time.perf_counter_ns()-start)/1e6,'artifact':str(directory.relative_to(root/'results'))};rows.append(row);(directory/'stdout.log').write_bytes(r.stdout);(directory/'stderr.log').write_bytes(r.stderr)
            with (out/'timings.ndjson').open('a') as f:f.write(json.dumps(row)+'\n')
    valid=[r for r in rows if not r['warmup'] and r['exit']==0];pairs=[{r['mode']:r['elapsed_ms'] for r in valid if r['pair']==i} for i in range(a.samples)];pairs=[r for r in pairs if len(r)==2];diff=[r['after']-r['before'] for r in pairs];rng=random.Random(20261013);boots=sorted(statistics.median(rng.choices(diff,k=len(diff))) for _ in range(10000)) if diff else []
    result={'schema':'vault-binary-startup-pairs/1','same_profile':True,'seed':20261013,'samples':a.samples,'valid_pairs':len(pairs),'failed_measured':[r for r in rows if not r['warmup'] and r['exit']!=0],'before_median_ms':statistics.median(r['before'] for r in pairs) if pairs else None,'after_median_ms':statistics.median(r['after'] for r in pairs) if pairs else None,'paired_extra_median_ms':statistics.median(diff) if diff else None,'bootstrap_ci95_ms':[boots[249],boots[9749]] if boots else None,'binary_sha256':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in bins.items()},'profile_sha256':hashlib.sha256(profile.encode()).hexdigest(),'no_provider_latency':True}
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
