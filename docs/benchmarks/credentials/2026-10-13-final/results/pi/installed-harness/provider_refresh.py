#!/usr/bin/env python3
"""One authorized OpenAI grant with forced expiry metadata, no token output.
The access JWT can still be valid; this is explicitly not natural-expiry proof.
Only the benchmark's private import is changed. The caller synchronizes any
rotated grant back into the authorized host login caches through a private CAS.
"""
import argparse,base64,json,os,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--auth-file',type=Path,required=True);p.add_argument('--out-name',default='provider-refresh');a=p.parse_args();root=a.root.resolve();out=root/'results'/a.out_name;out.mkdir();private=root/'private';private.mkdir(mode=0o700,exist_ok=True)
    auth=json.loads(a.auth_file.read_text());snapshot=private/'auth-before-refresh.json';snapshot.write_text(json.dumps(auth));snapshot.chmod(0o600);tokens=auth['tokens'];payload=tokens['access_token'].split('.')[1];expiry=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))['exp']
    source=private/'codex-token.json';document={k:tokens[k] for k in ('access_token','refresh_token','id_token')};document['expires_at']=0;source.write_text(json.dumps(document));source.chmod(0o600)
    config=root/'provider-refresh-private/config/launch';config.mkdir(parents=True,mode=0o700);workspace=root/'provider-refresh-work';workspace.mkdir();profile='name="refresh"\njail="agent"\nhome_is_state=true\n[credentials.api]\nmode="vault"\nsource='+json.dumps(str(source))+'\nhosts=["https://chatgpt.com"]\npaths=["/backend-api/"]\nbinaries='+json.dumps([str((root/'bin/codex').resolve())])+'\nheader={name="authorization",prefix="Bearer "}\nrefresh={token_url="https://auth.openai.com/oauth/token",client_id="app_EMoamEEZ73f0CkXaXp7hrann",refresh_before_seconds=300,encoding="json"}\n[network]\nallow=["chatgpt.com:443"]\n';(config/'refresh.toml').write_text(profile);(config/'refresh.toml').chmod(0o600)
    env=dict(os.environ,OURO_CONFIG_DIR=str(config.parent),OURO_DATA_DIR=str(root/'data'));env.pop('ANTHROPIC_API_KEY',None);start=time.monotonic();r=subprocess.run([str(root/'bin/ouro-jail'),'run','--launch','refresh','--workspace',str(workspace),'--limit','wall=20s','--receipt',str(out/'jail.json'),'--','/bin/true'],env=env,capture_output=True,timeout=40)
    for name,value in [('stdout',r.stdout),('stderr',r.stderr)]:
        for token in tokens.values():
            if isinstance(token,str) and token:value=value.replace(token.encode(),b'<PRIVATE_LOGIN_VALUE>')
        (out/(name+'.log')).write_bytes(value)
    new=json.loads(source.read_text());receipt=json.loads((out/'jail.json').read_text());journal=root/'data/attempts'/receipt['attempt_id']/'trace.ndjson'
    if journal.exists():(out/'trace.ndjson').write_bytes(journal.read_bytes())
    result={'schema':'real-provider-refresh/1','provider':'OpenAI OAuth2','token_url':'https://auth.openai.com/oauth/token','public_client_id':'app_EMoamEEZ73f0CkXaXp7hrann','forced_expiry_metadata':True,'original_jwt_valid_at_start':expiry>int(time.time()),'original_jwt_expiry_unix':expiry,'natural_expiry_exercised':False,'exit':r.returncode,'elapsed_ms':(time.monotonic()-start)*1000,'source_pending_after':new.get('refresh_pending',False),'access_rotated':new['access_token']!=tokens['access_token'],'refresh_rotated':new['refresh_token']!=tokens['refresh_token'],'expires_after_unix':new['expires_at'],'success':r.returncode==0 and new['expires_at']>int(time.time()) and not new.get('refresh_pending',False),'actual_credential_values_retained':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
    if not result['success']:raise SystemExit(1)
if __name__=='__main__':main()
