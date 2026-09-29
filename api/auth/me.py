import json
from http.server import BaseHTTPRequestHandler
from api._db import authenticate_request


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"authenticated": False})
        return self.send_json(200, {
            "authenticated": True,
            "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
        })
