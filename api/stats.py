"""
api/stats.py — Vercel Python Serverless Function
GET /api/stats
"""
from http.server import BaseHTTPRequestHandler
import json, os

STATS_PATH = os.path.join(os.path.dirname(__file__), '..', 'backend', 'models', 'model_stats.json')

def _load_stats():
    try:
        with open(STATS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

_stats = _load_stats()


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not _stats:
            self._send(503, json.dumps({"error": "Model stats not available"}))
            return
        body = json.dumps({
            "model":          _stats.get("model", "SoftVotingEnsemble_v2"),
            "accuracy":       _stats.get("accuracy", 0),
            "f1_score":       _stats.get("f1_score", 0),
            "roc_auc":        _stats.get("roc_auc", 0),
            "dataset_size":   _stats.get("dataset_size", 0),
            "features_count": _stats.get("features_count", 38),
            "training_date":  _stats.get("training_date", "unknown"),
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
