#!/usr/bin/env python3
"""Real Linux CLI acceptance. Fixture credentials have no external authority."""
import argparse
import http.server
import json
import os
import pathlib
import pty
import select
import hashlib
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--out', type=pathlib.Path, required=True)
args = parser.parse_args()
os.umask(0o077)
root = pathlib.Path(tempfile.mkdtemp(prefix='.ouro-acceptance-', dir=pathlib.Path.home()))
work, config, data = (root / name for name in ('work', 'config', 'data'))
work.mkdir(); config.mkdir(); (config/'launch').mkdir()
env = os.environ | {'OURO_CONFIG_DIR': str(config), 'OURO_DATA_DIR': str(data)}
binary = args.binary.resolve()
results = []
receipts = args.out.with_suffix('')
receipts.mkdir(parents=True, exist_ok=True)
def command(flags, argv, expected, label, verb='run'):
    before = set((data/'attempts').glob('*'))
    p = subprocess.run([str(binary), verb, *([] if '--workspace' in flags else ['--workspace', str(work)]), *flags, '--', *argv], env=env, capture_output=True, text=True, timeout=40)
    results.append({'case': label, 'code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    assert p.returncode in (expected if isinstance(expected, tuple) else (expected,)), results[-1]
    if isinstance(expected, tuple) and p.returncode == 1:
        assert 'error exec_unconfirmed at ' in p.stderr, results[-1]
        results[-1]['exec_confirmation'] = 'unconfirmed; syscall result observed in fixture stdout'
    errors = {
        'writable_binary_root_refused': 'unsafe_state_path',
        'pseudo_fs_workspace_refused': 'policy_widening',
        'profile_fifo_refused': 'invalid_config',
        'profile_symlink_refused': 'invalid_config',
        'profile_oversize_refused': 'invalid_config',
        'root_exec_denied': 'exec_failed',
        'none_refuses_trusted_config': 'unsafe_config_path',
        'command_forbid': 'command_forbidden',
    }
    if label in errors: assert 'error '+errors[label]+' at ' in p.stderr, results[-1]
    for attempt in set((data/'attempts').glob('*')) - before:
        receipt = attempt/'jail.json'
        if receipt.exists():
            name = f'{len(results):02d}-{label}.json'
            shutil.copyfile(receipt, receipts/name)
            results[-1]['receipt'] = receipts.name+'/'+name
    return p
def latest():
    return max((data/'attempts').iterdir(), key=lambda p: p.stat().st_mtime_ns)
try:
    fixture_dir = pathlib.Path(__file__).resolve().parent/'fixtures'
    for source in ['a5_c3.c','a5_sysprobe.c','clone3_x32.c','learn_access.c']:
        subprocess.run(['cc','-O2',str(fixture_dir/source),'-o',str(work/source[:-2])],check=True)
    for profile, expected_errno in [('none',4294967258),('tool',4294967258),('agent',4294967258)]:
        p=command(['--profile',profile,'--observe','on'],[str(work/'a5_c3')],0,'compat_clone3_'+profile)
        assert f'clone3 returned {expected_errno}' in p.stdout and 'CHILD alive' not in p.stdout, p.stdout
    for profile in ['none','tool','agent']:
        p=command(['--profile',profile,'--observe','on'],[str(work/'clone3_x32')],0,'x32_clone3_'+profile)
        assert 'x32 clone3 errno=38' in p.stdout
    for profile in ['tool','agent']:
        p=command(['--profile',profile,'--observe','off'],[str(work/'a5_c3')],(0,1),'compat_clone3_unobserved_'+profile)
        assert 'clone3 returned 4294967295' in p.stdout and 'CHILD alive' not in p.stdout
    probe_target=root/'probe-readonly'; probe_target.write_text('fixture')
    p=command(['--profile','tool','--ro',str(probe_target)],[str(work/'a5_sysprobe'),str(probe_target)],0,'kernel_surface_denied')
    for name in ['settimeofday','setxattrat','getxattrat','open_tree_attr','file_getattr','listns','file_setattr']:
        assert any(line.startswith(name) and 'errno=1 ' in line for line in p.stdout.splitlines()),p.stdout
    for flag, root_path in [('--rw',str(binary.parent)),('--rw','/usr/bin')]:
        command(['--profile','tool',flag,root_path],['/bin/true'],125,'writable_binary_root_refused')
    command(['--profile','tool','--workspace','/dev/shm'],['/bin/true'],125,'pseudo_fs_workspace_refused')
    fifo=root/'profile-fifo'; os.mkfifo(fifo)
    command(['--profile',str(fifo)],['/bin/true'],2,'profile_fifo_refused')
    link=root/'profile-link'; link.symlink_to('/dev/zero')
    command(['--profile',str(link)],['/bin/true'],2,'profile_symlink_refused')
    huge=root/'profile-huge'; huge.write_bytes(b'x'*(256*1024+1))
    command(['--profile',str(huge)],['/bin/true'],2,'profile_oversize_refused')
    for rule in ('deny', 'forbid'):
        (config/'config.toml').write_text('[jail.commands]\n'+rule+' = ["touch forbidden"]\n')
        p = command(['--profile','tool','--observe','on'], ['/bin/sh','-c','touch forbidden; sleep .1; printf continued'], 0 if rule=='deny' else 1, 'command_'+rule)
        assert not (work/'forbidden').exists()
        events=[json.loads(line) for line in (latest()/'trace.ndjson').read_text().splitlines()]
        assert any(e['fields'].get('kind')=='command_'+('denied' if rule=='deny' else 'forbidden') for e in events)
    (config/'config.toml').write_text('[jail.commands]\ndeny = ["touch forbidden"]\n')
    command(['--profile','tool','--observe','on'],['/usr/bin/touch','forbidden'],125,'root_exec_denied')
    assert not (work/'forbidden').exists()
    command(['--profile','tool','--observe','on'],['/bin/sh','-c','printf permitted > forbidden'],0,'command_rules_are_not_an_effect_boundary')
    (work/'forbidden').unlink()
    (config/'config.toml').write_text('[jail]\n')
    command(['--profile','none'], ['/bin/true'], 125, 'none_refuses_trusted_config')
    (config/'config.toml').unlink()
    outside=root/'outside.txt'; outside.write_text('read-only fixture')
    proposal=root/'proposal.toml'
    command(['--profile','tool','--out',str(proposal)], [str(work/'learn_access'),'read',str(outside)], 1, 'learning_exact_existing_object', verb='learn')
    learned=tomllib.loads(proposal.read_text()); assert learned['read_only']==[str(outside)], learned
    assert learned['provenance']['receipt_digest']=='sha256:'+hashlib.sha256((latest()/'jail.json').read_bytes()).hexdigest()
    directory=root/'read-directory'; directory.mkdir(); (directory/'item').write_text('fixture')
    directory_proposal=root/'directory.toml'
    command(['--profile','tool','--out',str(directory_proposal)], [str(work/'learn_access'),'directory',str(directory)], 1, 'learning_exact_directory', verb='learn')
    directory_learned=tomllib.loads(directory_proposal.read_text())
    assert directory_learned['read_only']==[str(directory)], directory_learned
    hosts_proposal=root/'hosts.toml'
    command(['--profile','agent','--out',str(hosts_proposal)], ['/bin/sh','-c','curl -fsS https://first.invalid/; curl -fsS https://second.invalid/; exit 0'], 0, 'learning_two_denied_hosts', verb='learn')
    host_learned=tomllib.loads(hosts_proposal.read_text())
    assert set(host_learned['network_allow'])=={'first.invalid:443','second.invalid:443'},host_learned
    writes_proposal=root/'writes.toml'
    command(['--profile','tool','--ro',str(outside),'--out',str(writes_proposal)], [str(work/'learn_access'),'write',str(outside)], 1, 'learning_denied_write_never_granted', verb='learn')
    write_learned=tomllib.loads(writes_proposal.read_text())
    assert write_learned['denied_writes'] and not write_learned['read_only'] and not write_learned['network_allow'],write_learned
    assert outside.read_text()=='read-only fixture'
    no_tty=subprocess.run([str(binary),'learn','--adopt','--workspace',str(work),'--','/bin/true'],env=env,capture_output=True,timeout=10)
    assert no_tty.returncode!=0 and b'interactive terminal' in no_tty.stderr
    results.append({'case':'adoption_requires_tty'})
    master,slave=pty.openpty()
    proc=subprocess.Popen([str(binary),'learn','--adopt','--out',str(root/'adopt.toml'),'--workspace',str(work),'--profile','tool','--',str(work/'learn_access'),'read',str(outside)],env=env,stdin=slave,stdout=slave,stderr=slave)
    os.close(slave); transcript=b''; answered=False; deadline=time.monotonic()+40
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],.1)[0]:
                try: block=os.read(master,65536)
                except OSError: break
                if not block: break
                transcript+=block
                if b'Type yes:' in transcript and not answered:
                    os.write(master,b'yes\n'); answered=True
            if proc.poll() is not None: break
        assert answered and proc.wait(timeout=2)==1,transcript.decode(errors='replace')
    finally:
        os.close(master)
        if proc.poll() is None: proc.kill();proc.wait()
    assert str(outside) in tomllib.loads((config/'config.toml').read_text())['jail']['filesystem']['read_only']
    command(['--profile','tool'],[str(work/'learn_access'),'read',str(outside)],0,'adopted_exact_read_applies')
    (config/'config.toml').unlink()
    trace=(latest()/'trace.ndjson').read_bytes()
    tail=subprocess.run([str(binary),'tail','--attempt',latest().name,'--json'],env=env,capture_output=True,timeout=10)
    assert tail.returncode==0 and tail.stdout==trace
    results.append({'case':'settled_tail_byte_equality','bytes':len(trace)})
    proc=subprocess.Popen([str(binary),'run','--profile','tool','--observe','on','--workspace',str(work),'--','/bin/sh','-c','sleep 1; printf done'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        attempt=latest()
        if (attempt/'trace.ndjson').exists() and (attempt/'trace.ndjson').read_bytes()!=trace: break
        time.sleep(.02)
    follow=subprocess.Popen([str(binary),'tail','--attempt',attempt.name,'--follow','--json'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    proc.communicate(timeout=15); out,err=follow.communicate(timeout=15)
    assert follow.returncode==0 and out==(attempt/'trace.ndjson').read_bytes(), err
    results.append({'case':'live_tail_byte_equality','bytes':len(out)})
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.headers.get('Authorization')=='Bearer fixture-secret'
            assert self.headers.get('Proxy-Authorization') is None
            self.send_response(200); self.end_headers(); self.wfile.write(b'vault-ok')
        def log_message(self,*args): pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler); port=server.server_port
    threading.Thread(target=server.serve_forever,daemon=True).start()
    source=root/'token'; source.write_text('Bearer fixture-secret')
    (config/'launch/vault.toml').write_text(f'''name = "vault"
jail = "agent"
home_is_state = true
[credentials.api]
mode = "vault"
source = "{source}"
hosts = ["http://127.0.0.1:{port}"]
allow_plaintext = true
[network]
allow = ["127.0.0.1:{port}"]
''')
    p=command(['--launch','vault'], ['/bin/sh','-c',f'printf "%s\\n" "$OURO_VAULT_API"; curl -fsS --noproxy "" -H "Authorization: $OURO_VAULT_API" http://127.0.0.1:{port}/'],0,'http_vault_live')
    assert 'vault:' in p.stdout and 'vault-ok' in p.stdout and 'fixture-secret' not in p.stdout
    attempt=latest(); receipt=json.loads((attempt/'jail.json').read_text())
    assert receipt['credentials'][0]['never_staged'] is True
    assert b'fixture-secret' not in (attempt/'trace.ndjson').read_bytes()+(attempt/'jail.json').read_bytes()
    assert not (attempt/'vendor-state').exists()
    results.append({'case':'vault_vendor_state_removed'})
    server.shutdown()
    # No trust bypass: a real HTTPS request validates the public upstream chain.
    p=command(['--launch','vault','--allow-host','example.com'], ['/bin/sh','-c','curl -fsS https://example.com/ >/dev/null'],0,'https_vault_real_chain')
    command(['--launch','vault','--allow-host','example.com'], ['/bin/sh','-c','curl -fsS --proxy socks5h://127.0.0.1:3129 https://example.com/ >/dev/null'],0,'socks5_real_tls')
    for name in ['codex','claude','opencode','cursor','aider','goose','gemini','amp','cline','copilot','kilo','auggie','droid','pi']:
        p=subprocess.run([str(binary),'doctor','--launch',name,'--json'],env=env,cwd=work,capture_output=True,text=True,timeout=20)
        report=json.loads(p.stdout); assert report['launch']['resolution']=='bundled' and report['ready'],report
        results.append({'case':'bundled_doctor','name':name,'code':p.returncode,'ready':report['ready']})
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps({'build':json.loads(subprocess.check_output([str(binary),'version','--json'])),'results':results},indent=2)+'\n')
    print(f'PASS: {len(results)} live checks; {args.out}')
finally:
    shutil.rmtree(root)
