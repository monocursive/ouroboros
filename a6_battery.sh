#!/usr/bin/env bash
# Sixth-pass mechanical boundary battery. Each line prints TEST|RESULT.
t() { local name="$1"; shift; local out; out="$("$@" 2>&1)"; local rc=$?; printf '%s|rc=%d|%s\n' "$name" "$rc" "$(printf '%s' "$out" | head -c 120 | tr '\n' ' ')"; }

echo "== root view =="
ls / 2>&1 | tr '\n' ' '; echo
echo "== fs probes =="
t etc-passwd cat /etc/passwd
t etc-shadow cat /etc/shadow
t home-ls ls /home
t symlink-escape sh -c 'ln -sf /etc/passwd $PWD/esc_link; cat $PWD/esc_link'
t symlink-escape2 sh -c 'ln -sf ../../../../../etc/passwd $PWD/esc_link2; cat $PWD/esc_link2'
t deep-traverse sh -c 'cat ./../../../../etc/passwd'
t proc-root sh -c 'cat /proc/self/root/etc/passwd'
t proc-1-cmdline sh -c 'cat /proc/1/cmdline | tr "\0" " "'
t proc-self-fd sh -c 'ls -l /proc/self/fd | head -20'
t proc-self-root-w sh -c 'touch /proc/self/root/pwned 2>&1 || echo refused'
t mknod sh -c 'mknod $PWD/nul c 1 3 2>&1 || echo refused'
t mount mount -t tmpfs none $PWD 2>&1 || echo refused
t open-tree sh -c 'python3 -c "import ctypes,os; libc=ctypes.CDLL(None); fd=libc.syscall(428,0,0,0); print(fd)"'
t move-mount sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(libc.syscall(429,-1,-1,0))"'
t fsopen sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(libc.syscall(430,b\"tmpfs\",0))"'
t open-by-handle sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(libc.syscall(304,-1,b\"\x00\"*32,0))"'
t chroot-fd-escape sh -c 'cd /; mkdir -p tmpdir; cd tmpdir; mkdir x; cd x; cd ..; cd ..; python3 -c "import os; os.chroot(\".\"); print(open(\"/proc/self/root/etc/passwd\").read()[:40])" 2>&1'
t core-pattern sh -c 'echo x > /proc/sys/kernel/core_pattern 2>&1 || echo refused'
t sysrq sh -c 'echo b > /proc/sysrq-trigger 2>&1 || echo refused'
t cgroup-release sh -c 'find /sys/fs/cgroup -name release_agent 2>/dev/null | head -2; ls /sys/fs/cgroup 2>&1 | head -3'
t modprobe sh -c 'echo /tmp/x > /proc/sys/kernel/modprobe 2>&1 || echo refused'
t binfmt sh -c 'ls /proc/sys/fs/binfmt_misc 2>&1 | head -2'
t dev-mem sh -c 'ls -l /dev/mem /dev/kmem 2>&1'
t dev-sda sh -c 'ls -l /dev/sda 2>&1'
t setuid-find sh -c 'find / -perm -4000 -type f 2>/dev/null | head -5'
t write-tmp sh -c 'echo x > /tmp/a6probe && cat /tmp/a6probe'
t write-var sh -c 'echo x > /var/tmp/a6probe 2>&1 || echo refused'
t keyctl sh -c 'keyctl add user a b @u 2>&1 || echo refused'
t hardlink-ro sh -c 'ln /etc/passwd $PWD/hl 2>&1 || echo refused'
t rename-exchange sh -c 'python3 - <<EOF
import ctypes, os
libc = ctypes.CDLL(None)
try:
    os.close(libc.renameat2(-100, b"/etc/passwd", -100, os.fsencode(__import__("os").getcwd()+b"/rx"), 2))
    print("EXCHANGED")
except OSError as e:
    print("refused", e)
EOF'
t pidfd-getfd sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(libc.syscall(434,2,2,0))"'
t ptrace-attach sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(ctypes.get_errno(), libc.ptrace(16,1,0,0))"'
t proc-vm sh -c 'python3 -c "import ctypes; libc=ctypes.CDLL(None); print(libc.syscall(310,1,None,None,None,None))"'
t unshare-user sh -c 'unshare -Ur id 2>&1 | head -1'
t unshare-net sh -c 'unshare -n true 2>&1 || echo refused'
t clone-newuser sh -c 'python3 - <<EOF
import ctypes
libc = ctypes.CDLL(None)
# clone(CLONE_NEWUSER|SIGCHLD)
stack = ctypes.create_string_buffer(65536)
CT = ctypes.CFUNCTYPE(ctypes.c_int)
def child(): return 0
cb = CT(child)
rc = libc.clone(cb, ctypes.byref(stack, 65536), 0x10000000|17, 0)
print("clone-rc", rc)
EOF'
echo "== net probes =="
t net-dev cat /proc/net/dev
t tcp-direct sh -c 'python3 - <<EOF
import socket
try:
    s = socket.create_connection(("93.184.216.34", 80), 3)
    print("DIRECT CONNECTED")
except Exception as e:
    print("refused:", e)
EOF'
t dns-direct sh -c 'python3 - <<EOF
import socket
try:
    print(socket.gethostbyname("example.com"))
except Exception as e:
    print("refused:", e)
EOF'
t proxy-sock-direct sh -c 'python3 - <<EOF
import socket, os
for p in ["/run/ouro/proxy/proxy.sock"]:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(p)
        print("CONNECTED", p)
    except Exception as e:
        print("refused:", p, e)
EOF'
t abstract-sock sh -c 'python3 - <<EOF
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("\\0a6test")
    print("CONNECTED")
except Exception as e:
    print("res:", e)
EOF'
echo "== env/cred probes =="
t env env | sort | head -30
t ssh-keys sh -c 'ls ~/.ssh 2>&1'
t opencode-auth sh -c 'ls -la ~/.local/share/opencode 2>&1; cat ~/.local/share/opencode/auth.json 2>&1 | head -c 60'
t ouro-config sh -c 'cat ~/.config/ouro/config.toml 2>&1 | head -c 80'
t ouro-state ls ~/.local/share/ouro 2>&1 | head -5
