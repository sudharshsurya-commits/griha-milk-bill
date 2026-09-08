import json
import secrets
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from api._db import get_db, verify_password

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
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        username = body.get("username", "").strip()
        password = body.get("password", "").strip()

        if not username or not password:
            return self.send_json(400, {"error": "Username and password are required"})

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, password_hash, salt FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if not row or not verify_password(row["password_hash"], row["salt"], password):
                    return self.send_json(401, {"error": "Invalid username or password"})

                token = secrets.token_hex(32)
                expires = datetime.utcnow() + timedelta(days=30)
                cur.execute(
                    "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
                    (token, row["id"], expires)
                )
                conn.commit()

                return self.send_json(200, {
                    "token": token,
                    "user": {"id": row["id"], "username": row["username"]},
                    "message": "Login successful"
                })
        except Exception as e:
            print("[LOGIN ERROR]", e)
            return self.send_json(500, {"error": "Database error during login", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
