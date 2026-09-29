#!/usr/bin/env python3
"""Reproduce the lifecycle limit of process-group cleanup under native Seatbelt."""
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
with tempfile.TemporaryDirectory(prefix='ouro-seatbelt-probe-') as directory:
    root=pathlib.Path(directory)
    source=root/'detach.c'
    source.write_text('''#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) { pid_t child=fork(); if(child<0) return 2; if(child==0) { if(setsid()<0) _exit(3); close(1); close(2); sleep(30); _exit(0); } printf("%d\\n",child); fflush(stdout); sleep(1); return 0; }
''')
    subprocess.run(['cc',str(source),'-o',str(root/'detach')],check=True)
    policy='(version 1)(deny default)(allow process-exec)(allow process-fork)(allow file-read*)(allow sysctl-read)(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))'
    parent=subprocess.Popen(['/usr/bin/sandbox-exec','-p',policy,str(root/'detach')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,text=True)
    child=None
    try:
        child=int(parent.stdout.readline());time.sleep(.1)
        detached=os.getsid(child)==child
        os.killpg(parent.pid,signal.SIGTERM)
        parent.wait(timeout=5)
        os.kill(child,0)
        print(json.dumps({'test':'seatbelt_process_group_descendant_cleanup','detached_with_setsid':detached,'child_alive_after_group_termination':True,'policy':policy,'meaning':'native process-group cleanup cannot establish tree_empty'},indent=2))
        assert detached
    finally:
        if child:
            try: os.kill(child,signal.SIGKILL)
            except ProcessLookupError: pass
        if parent.poll() is None: parent.kill();parent.wait()
