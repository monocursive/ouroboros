#!/usr/bin/env python3
"""Common real-clock synthetic OAuth issuer/resource, never a credential broker.

Refresh grants are single-use. Issued access tokens retain their own actual
expiry, as ordinary OAuth bearer tokens can. Products alone own refresh and
substitution. Lost-response mode consumes a grant before dropping its response.
"""
import http.server
import json
import re
import socket
import threading
import time
import urllib.parse


class Issuer:
    def __init__(self, nonce, lifetime=180, lose_generation=None):
        self.nonce = nonce
        self.lifetime = lifetime
        self.lose_generation = lose_generation
        self.lock = threading.RLock()
        self.generation = 0
        self.expires = {0: int(time.time()) + lifetime}
        self.events = []

    def access(self, generation):
        return f'fixture-access-{self.nonce}-{generation}'

    def refresh(self, generation):
        return f'fixture-refresh-{self.nonce}-{generation}'

    def initial(self):
        with self.lock:
            return {'access_token': self.access(0), 'refresh_token': self.refresh(0),
                    'expires_at': self.expires[0]}

    def grant(self, fields):
        with self.lock:
            valid = (fields.get('grant_type') == ['refresh_token']
                     and fields.get('client_id') == ['fixture-client']
                     and fields.get('refresh_token') == [self.refresh(self.generation)])
            row = {'kind': 'grant', 'unix': time.time(),
                   'prior_generation': self.generation, 'accepted': valid}
            if not valid:
                self.events.append(row)
                return 400, {'error': 'invalid_grant'}, False
            self.generation += 1
            self.expires[self.generation] = int(time.time()) + self.lifetime
            lose = self.generation == self.lose_generation
            row.update({'issued_generation': self.generation,
                        'expires_at': self.expires[self.generation],
                        'response_deliberately_lost': lose})
            self.events.append(row)
            return 200, {'access_token': self.access(self.generation),
                         'refresh_token': self.refresh(self.generation),
                         'expires_in': self.lifetime, 'token_type': 'Bearer'}, lose

    def resource(self, authorization, request_id, client_pid):
        with self.lock:
            prefix = 'Bearer fixture-access-' + self.nonce + '-'
            generation = None
            if authorization and authorization.startswith(prefix):
                suffix = authorization[len(prefix):]
                if re.fullmatch(r'\d+', suffix):
                    generation = int(suffix)
            expiry = self.expires.get(generation)
            accepted = expiry is not None and time.time() < expiry
            row = {'kind': 'resource', 'unix': time.time(), 'request_id': request_id,
                   'client_pid_claim': client_pid, 'generation': generation,
                   'current_issuer_generation': self.generation, 'accepted': accepted,
                   'token_expiry': expiry, 'expired_token': bool(expiry and time.time() >= expiry)}
            self.events.append(row)
            return row.copy()

    def snapshot(self):
        with self.lock:
            return {'generation': self.generation, 'access_expiries': self.expires.copy(),
                    'events': [row.copy() for row in self.events],
                    'actual_credential_values_retained': False,
                    'real_clock_modified': False, 'forced_expiry_metadata': False}


def servers(state, resource_host):
    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if not self.server.issuer or self.path != '/token':
                self.reply(404, {'error': 'wrong_endpoint'})
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if length <= 0 or length > 8192:
                    raise ValueError('invalid body length')
                fields = urllib.parse.parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
            except (ValueError, UnicodeError):
                self.reply(400, {'error': 'invalid_request'})
                return
            status, body, lose = state.grant(fields)
            if lose:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.reply(status, body)

        def do_GET(self):
            if self.server.issuer or urllib.parse.urlsplit(self.path).path != '/v1/probe':
                self.reply(404, {'error': 'wrong_endpoint'})
                return
            if self.headers.get('X-Fixture-Run') != state.nonce:
                self.reply(403, {'error': 'wrong_fixture'})
                return
            result = state.resource(self.headers.get('Authorization'),
                                    self.headers.get('X-Fixture-Request'),
                                    self.headers.get('X-Fixture-Client'))
            self.reply(200 if result['accepted'] else 401, result)

        def log_message(self, *_):
            pass

    resource = http.server.ThreadingHTTPServer((resource_host, 0), Handler)
    issuer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    resource.issuer = False
    issuer.issuer = True
    for server in (resource, issuer):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return resource, issuer
