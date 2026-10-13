#!/usr/bin/env python3
"""Real jail lifecycle/binding fixtures; only nonsecret synthetic tokens."""
import argparse, http.server, json, os, shlex, subprocess, threading, time
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);args=parser.parse_args()
    root=args.root.resolve();out=root/'results/lifecycle';out.mkdir();private=root/'lifecycle-private';private.mkdir(mode=0o700)
    work=root/'lifecycle-work';work.mkdir();config=private/'config/launch';config.mkdir(parents=True);source=private/'token';source.write_text('fixture-v1');source.chmod(0o600)
    received=[];stream_started=threading.Event();issuer_started=threading.Event();issuer_continue=threading.Event();issuer_mode={'value':'success'}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value=self.headers.get('x-api-key');received.append({'path':self.path,'v1':value=='fixture-v1','v2':value=='fixture-v2','new':value=='new-access'})
            self.send_response(200);self.send_header('Connection','close');self.end_headers()
            if self.path=='/v1/stream':
                stream_started.set()
                try:
                    for _ in range(1000):self.wfile.write(b'fixture-stream\n');self.wfile.flush();time.sleep(.03)
                except (BrokenPipeError,ConnectionResetError):pass
            else:self.wfile.write(b'fixture-ok')
        def do_POST(self):
            data=self.rfile.read(int(self.headers['Content-Length']));mode=issuer_mode['value'];issuer_started.set()
            if mode=='blocked':issuer_continue.wait(10)
            body=json.dumps({'access_token':'new-access','refresh_token':'new-refresh','expires_in':3600,'token_type':'Bearer'}).encode()
            if mode=='failure':body=b'{"error":"invalid_grant"}'
            self.send_response(400 if mode=='failure' else 200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
            received.append({'issuer':True,'old_refresh_received':b'refresh_token=old-refresh' in data,'mode':mode})
        def log_message(self,*_):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();origin='http://127.0.0.1:'+str(server.server_port)
    env=dict(os.environ,OURO_CONFIG_DIR=str(config.parent),OURO_DATA_DIR=str(root/'data'));env.pop('ANTHROPIC_API_KEY',None)
    checks=[];curl=str(Path('/usr/bin/curl').resolve());python=str(Path('/usr/bin/python3').resolve());counter=0
    def profile(paths=None,binaries=None,refresh=False):
        text='name="probe"\njail="agent"\nhome_is_state=true\n[credentials.api]\nmode="vault"\nsource='+json.dumps(str(source))+'\nhosts='+json.dumps([origin])+'\nallow_plaintext=true\nheader={name="x-api-key"}\n'
        if paths is not None:text+='paths='+json.dumps(paths)+'\n'
        if binaries is not None:text+='binaries='+json.dumps(binaries)+'\n'
        if refresh:text+='refresh={token_url='+json.dumps(origin+'/token')+',client_id="fixture-client",refresh_before_seconds=0}\n'
        text+='[network]\nallow='+json.dumps(['127.0.0.1:'+str(server.server_port)])+'\n';(config/'probe.toml').write_text(text);(config/'probe.toml').chmod(0o600)
    def request(path='/v1/messages'):
        return shlex.quote(curl)+' -fsS --no-buffer --max-time 15 --noproxy "" -H "x-api-key: $OURO_VAULT_API" '+shlex.quote(origin+path)
    def start(name,command):
        nonlocal counter;counter+=1;directory=out/('%02d-'%counter+name);directory.mkdir()
        argv=[str(root/'bin/ouro-jail'),'run','--launch','probe','--workspace',str(work),'--limit','wall=25s','--receipt',str(directory/'jail.json'),'--','/bin/sh','-c',command]
        process=subprocess.Popen(argv,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);return process,directory
    def finish(pair,name,expected,extra=None):
        process,directory=pair;stdout,stderr=process.communicate(timeout=35);(directory/'stdout.log').write_bytes(stdout);(directory/'stderr.log').write_bytes(stderr)
        receipt=json.loads((directory/'jail.json').read_text());trace=root/'data/attempts'/receipt['attempt_id']/'trace.ndjson'
        if trace.exists():(directory/'trace.ndjson').write_bytes(trace.read_bytes())
        row={'name':name,'exit':process.returncode,'expected':expected,'pass':bool(expected(process.returncode,stdout,stderr,receipt)),'artifact':str(directory.relative_to(root/'results'))};row['expected']=name
        if extra:row.update(extra)
        checks.append(row);return row
    def run(name,command,expected=lambda code,*_:code==0,**kwargs):profile(**kwargs);return finish(start(name,command),name,expected)
    def wait(path,pair):
        deadline=time.monotonic()+15
        while not path.exists():
            if pair[0].poll() is not None:raise RuntimeError('fixture ended before synchronization: '+str(path.name))
            if time.monotonic()>deadline:raise RuntimeError('fixture synchronization timeout')
            time.sleep(.01)
    def document(expiry):source.write_text(json.dumps({'access_token':'old-access','refresh_token':'old-refresh','expires_at':expiry}));source.chmod(0o600)
    try:
        run('bound-native-curl',request(),paths=['/v1/'],binaries=[curl]);assert received[-1]['v1']
        denied_start=len(received)
        run('wrong-initiator-even-with-claimed-pid',request()+' -H "X-Ouro-Process: curl"',lambda code,*_:code!=0,paths=['/v1/'],binaries=[python])
        run('outside-path',request('/outside'),lambda code,*_:code!=0,paths=['/v1/'],binaries=[curl])
        run('encoded-path-refused',request('/v1/%2e%2e/other'),lambda code,*_:code!=0,paths=['/v1/'],binaries=[curl])
        assert len(received)==denied_start
        profile(paths=['/v1/'],binaries=[curl]);pair=start('live-rotation',request()+' && touch rotation-ready; while test ! -f rotated; do sleep .01; done; '+request())
        wait(work/'rotation-ready',pair);source.write_text('fixture-v2');(work/'rotated').touch();finish(pair,'live-rotation',lambda code,*_:code==0);assert received[-2]['v1'] and received[-1]['v2']
        run('new-token-observed',request(),paths=['/v1/'],binaries=[curl])
        profile(paths=['/v1/'],binaries=[curl]);pair=start('stream-revocation',request('/v1/stream'));assert stream_started.wait(15);began=time.monotonic();source.unlink();row=finish(pair,'stream-revocation',lambda code,*_:code!=124);row['revocation_to_settled_ms']=(time.monotonic()-began)*1000;row['pass'] &= row['revocation_to_settled_ms']<2000
        run('source-deleted-preexec-refusal','touch must-not-execute',lambda code,stdout,stderr,r:code==125 and r['phase']=='refused',paths=['/v1/'],binaries=[curl]);assert not (work/'must-not-execute').exists()
        document(int(time.time())+100);profile(paths=['/v1/'],binaries=[curl],refresh=True);pair=start('idle-refresh','touch idle-ready; while test ! -f refreshed; do sleep .01; done; '+request());wait(work/'idle-ready',pair);document(int(time.time()))
        deadline=time.monotonic()+12
        while json.loads(source.read_text()).get('access_token')!='new-access':
            assert time.monotonic()<deadline;time.sleep(.02)
        (work/'refreshed').touch();finish(pair,'idle-refresh',lambda code,*_:code==0);assert received[-1]['new']
        issuer_mode['value']='blocked';issuer_started.clear();issuer_continue.clear();document(int(time.time()));profile(refresh=True);winner=start('concurrent-refresh-winner','true');assert issuer_started.wait(15)
        run('concurrent-attempt-cannot-reuse-pending-grant','true',lambda code,*_:code==125,refresh=True);issuer_continue.set();finish(winner,'concurrent-refresh-winner',lambda code,*_:code==0)
        issuer_mode['value']='failure';document(int(time.time()));run('invalid-grant-fails-closed','touch refresh-must-not-execute',lambda code,*_:code==125,refresh=True)
        assert json.loads(source.read_text())['refresh_pending'];assert not (work/'refresh-must-not-execute').exists()
        requests_before=sum('issuer' in r for r in received);run('pending-never-retries','true',lambda code,*_:code==125,refresh=True);assert requests_before==sum('issuer' in r for r in received)
        issuer_mode['value']='blocked';issuer_started.clear();issuer_continue.clear();document(int(time.time()));profile(refresh=True);pair=start('delete-during-refresh','touch exchange-must-not-execute');assert issuer_started.wait(15);source.unlink();issuer_continue.set();finish(pair,'delete-during-refresh',lambda code,*_:code==125);assert not source.exists();assert not (work/'exchange-must-not-execute').exists()
        result={'schema':'vault-lifecycle-security/2','checks':checks,'all_pass':all(r['pass'] for r in checks),'received':received,'only_synthetic_tokens':True,'binding':'kernel connection initiator; socket delegation is not per-byte attribution'}
        (out/'checks.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(checks),'all_pass':result['all_pass']}),flush=True)
        if not result['all_pass']:raise SystemExit(1)
    finally:issuer_continue.set();server.shutdown();server.server_close()
if __name__=='__main__':main()
