#!/usr/bin/env python3
"""SSRF/forbidden-address probe against the ukai proxy's DNS resolution.

Run a plain TCP marker listener on the VPS. Then from inside an agent-profile
jail with --allow-host for names that resolve to loopback/link-local/host IPs,
try to CONNECT and see whether the proxy refuses (forbidden-address table)
or connects.

Names tested (all resolve to 127.0.0.1 via nip.io unless local /etc/hosts
entries are used; local entries are planted first so no external DNS needed):
  loopback.local            -> 127.0.0.1   (via /etc/hosts, planted by runner)
  127-0-0-1.nip.io          -> 127.0.0.1
  metadata.local            -> 169.254.169.254
Decimal/octal/hex spellings are sent as literal CONNECT targets:
  2130706433, 0177.0.0.1, 0x7f.1, [::1], [::ffff:127.0.0.1]
"""
import socket, sys, threading, time

MARKER = b"SSRF_PROBE_REACHED_LISTENER"

def listener(port, results):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    s.settimeout(60)
    try:
        while True:
            c, _ = s.accept()
            data = c.recv(4096)
            results.append((port, data[:200]))
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            c.close()
    except socket.timeout:
        pass

def connect_via_proxy(proxy_addr, host, port):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(proxy_addr)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    s.sendall(req.encode())
    resp = s.recv(4096)
    s.close()
    return resp.split(b"\r\n")[0].decode(errors="replace")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "listener"
    if mode == "listener":
        results = []
        threads = []
        for port in (443, 3128):
            t = threading.Thread(target=listener, args=(port, results), daemon=True)
            t.start()
            threads.append(t)
        with open("/tmp/ssrf_listener_ready", "w") as f:
            f.write("ready")
        time.sleep(55)
        print("HITS:", results if results else "none")
    else:
        proxy = sys.argv[2]
        for host, port in [("loopback.local", 443),
                           ("127-0-0-1.nip.io", 443),
                           ("metadata.local", 80),
                           ("2130706433", 443),
                           ("0177.0.0.1", 443),
                           ("[::1]", 443)]:
            try:
                print(f"{host}:{port} ->", connect_via_proxy(proxy, host, port))
            except Exception as e:
                print(f"{host}:{port} -> ERROR {e}")
