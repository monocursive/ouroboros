#!/usr/bin/env python3
"""Pass-5 live battery: AF_UNIX mediation + bridge allowlist granularity.
Run INSIDE the jail (agent profile). Reports each result; failures that
should-have-refused are the findings."""
import socket, ssl, sys, os

def med(tag, fn):
    try:
        r = fn()
        print(f"{tag}: OK -> {r!r}")
    except OSError as e:
        print(f"{tag}: errno={e.errno} {e.strerror}")

# --- AF_UNIX mediation -------------------------------------------------
# 1. the bridge's own socket by path
med("connect proxy.sock direct", lambda: socket.socket(socket.AF_UNIX).connect("/run/ouro/proxy/proxy.sock"))
# 2. via symlink planted in vendor state (child-writable)
try:
    os.symlink("/run/ouro/proxy/proxy.sock", "/run/ouro/state/pl")
except OSError as e:
    print(f"symlink plant: errno={e.errno}")
med("connect via state symlink", lambda: socket.socket(socket.AF_UNIX).connect("/run/ouro/state/pl"))
# 3. overlong address
s = socket.socket(socket.AF_UNIX)
med("overlong addr", lambda: s.connect(b"/" + b"A"*200))
# 4. abstract socket (own netns)
def ab():
    a, b = socket.socketpair(socket.AF_UNIX)
    return "socketpair ok"
med("socketpair", ab)
# 5. nonexistent path under /run/ouro
med("connect nonexistent", lambda: socket.socket(socket.AF_UNIX).connect("/run/ouro/state/nope.sock"))
# 6. host path through .. escaping attempt dir
med("connect /../var/run", lambda: socket.socket(socket.AF_UNIX).connect("/run/ouro/../ouro/proxy/proxy.sock"))

# --- bridge: TCP battery ------------------------------------------------
def connect_raw(host, port, req, tls=None, sni=None, read_n=2000):
    s = socket.create_connection(("127.0.0.1", 3128), timeout=8)
    s.sendall(req)
    data = b""
    try:
        data = s.recv(read_n)
    except socket.timeout:
        data = b"<timeout>"
    s.close()
    return data[:200]

# 7. plain CONNECT to allowed host, then Host-header swap on the tunnel (port 80)
req = b"CONNECT registry.npmjs.org:80 HTTP/1.1\r\nHost: registry.npmjs.org:80\r\n\r\n"
print("CONNECT npmjs:80 ->", connect_raw("x", 0, req))
# follow with an HTTP request naming a different co-tenant Host
def tunnel_host_swap():
    s = socket.create_connection(("127.0.0.1", 3128), timeout=8)
    s.sendall(b"CONNECT registry.npmjs.org:80 HTTP/1.1\r\nHost: registry.npmjs.org:80\r\n\r\n")
    line = s.recv(4096)
    if b"200" not in line.split(b"\r\n")[0]:
        return f"tunnel refused: {line[:60]!r}"
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    import time; time.sleep(1)
    out = s.recv(4096)
    return out[:120]
print("host-swap via npmjs:80 ->", tunnel_host_swap())

# 8. TLS SNI swap on allowed CDN IP (443)
def sni_swap():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", 3128), timeout=8)
    s = ctx.wrap_socket(raw, server_hostname="registry.npmjs.org")  # SNI set here
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    import time; time.sleep(1)
    return s.recv(200)
med("TLS SNI=npmjs Host=example.com", sni_swap)

# 9. odd ports on allowed hosts
for port in (22, 25, 79, 8080, 3128):
    req = f"CONNECT registry.npmjs.org:{port} HTTP/1.1\r\nHost: registry.npmjs.org:{port}\r\n\r\n".encode()
    print(f"CONNECT npmjs:{port} ->", connect_raw("x", 0, req)[:60])

# 10. allowlist miss
req = b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"
print("CONNECT example.org ->", connect_raw("x", 0, req)[:60])
