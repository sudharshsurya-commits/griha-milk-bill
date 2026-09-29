import json
from http.server import BaseHTTPRequestHandler
from api._db import get_db, _load_fallback_store, _save_fallback_store


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")

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

    def _extract_token(self):
        auth = self.headers.get("authorization", self.headers.get("Authorization", ""))
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        cookie = self.headers.get("cookie", self.headers.get("Cookie", ""))
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("griha_token="):
                return part[len("griha_token="):]
        return ""

    def do_POST(self):
        token = self._extract_token()
        if not token:
            return self.send_json(200, {"message": "Logged out"})

        # 1. Primary: delete from PostgreSQL
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

        # 2. Fallback: add to revoked tokens list
        store = _load_fallback_store()
        revoked = store.setdefault("revoked_tokens", [])
        if token not in revoked:
            revoked.append(token)
            if len(revoked) > 1000:
                store["revoked_tokens"] = revoked[-500:]
            _save_fallback_store(store)

        return self.send_json(200, {"message": "Logged out successfully"})
