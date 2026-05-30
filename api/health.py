"""
api/health.py — Vercel Python Serverless Function
GET /api/health
"""
from http.server import BaseHTTPRequestHandler
import json, datetime


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "status": "ok",
            "model_loaded": True,
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": "2.0.0"
        })
        self._send(200, body)

    def do_OPTIONS(self):
        self._send(200, '{}')

    def _send(self, code, body):
        b = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Bypass-Tunnel-Reminder')
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, format, *args):
        pass
