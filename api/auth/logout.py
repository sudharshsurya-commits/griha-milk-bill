import json
from http.server import BaseHTTPRequestHandler
from api.db import get_db, authenticate_request

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        user = authenticate_request(self.headers)
        if user:
            conn = None
            try:
                conn = get_db()
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM sessions WHERE token = %s", (user["token"],))
                    conn.commit()
            except Exception as e:
                print("[LOGOUT ERROR]", e)
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
        return self.send_json(200, {"message": "Logged out successfully"})
