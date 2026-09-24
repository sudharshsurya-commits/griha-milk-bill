import json
from http.server import BaseHTTPRequestHandler
from api._db import get_db, authenticate_request, _load_fallback_store, _save_fallback_store

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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        user = authenticate_request(self.headers)
        if user and user.get("token"):
            token = user["token"]
            # 1. Primary: PostgreSQL
            conn = get_db()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
                        conn.commit()
                except Exception as e:
                    print("[LOGOUT DB ERROR]", e)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

            # 2. Resilient Fallback Store
            store = _load_fallback_store()
            if token in store.get("sessions", {}):
                del store["sessions"][token]
                _save_fallback_store(store)

        return self.send_json(200, {"message": "Logged out successfully"})
