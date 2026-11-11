"""Loopback-only native UI smoke fixture. Contains no real secrets or external links."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(2 if self.path.startswith('/slow') else 0.04)
        routes = {
            '/': ('text/html', '<html><title>Chaca local fixture</title><body><a href="/api/status">Status</a></body></html>'),
            '/api/status': ('application/json', '{"status":"ok","version":"fixture-1"}'),
            '/robots.txt': ('text/plain', 'User-agent: *\nDisallow: /admin\n'),
        }
        content_type, body = routes.get(self.path, ('text/plain', 'Not found'))
        self.send_response(200 if self.path in routes or self.path.startswith('/slow') else 404)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body.encode())))
        self.end_headers()
        try:
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

print('Chaca smoke fixture: http://127.0.0.1:38765', flush=True)
ThreadingHTTPServer(('127.0.0.1', 38765), Handler).serve_forever()
