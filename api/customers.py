import json
from http.server import BaseHTTPRequestHandler
from api.db import get_db, authenticate_request

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT name, phone, default_qty, default_unit, default_rate FROM customers WHERE user_id = %s ORDER BY name ASC", (user["id"],))
                rows = cur.fetchall()
                custs = [dict(r) for r in rows]
                return self.send_json(200, {"customers": custs})
        except Exception as e:
            print("[CUSTOMERS ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
