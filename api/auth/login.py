import json
import secrets
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from api._db import (
    get_db,
    verify_password,
    hash_password,
    create_session_token,
    ensure_db_initialized,
    _load_fallback_store,
)


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Suppress default access logs

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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        username = (body.get("username") or "").strip()
        password = (body.get("password") or "").strip()
        # Optional: caller may pass 'role' to restrict login to a specific role
        required_role = (body.get("role") or "").strip() or None

        if not username or not password:
            return self.send_json(400, {"error": "Username and password are required"})

        # ── 1. Primary: PostgreSQL ─────────────────────────────────────────
        conn = get_db()
        if conn:
            try:
                ensure_db_initialized(conn)
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, username, password_hash, salt, role FROM users WHERE LOWER(username) = LOWER(%s)",
                        (username,)
                    )
                    row = cur.fetchone()

                    if not row or not verify_password(row["password_hash"], row["salt"], password):
                        return self.send_json(401, {"error": "Invalid username or password"})

                    if required_role and row["role"] != required_role:
                        return self.send_json(401, {"error": "Invalid username or password"})

                    token = create_session_token(row["id"], row["username"], row["role"])
                    expires = datetime.utcnow() + timedelta(days=30)
                    try:
                        cur.execute(
                            """INSERT INTO sessions (token, user_id, role, expires_at)
                               VALUES (%s, %s, %s, %s)
                               ON CONFLICT (token) DO NOTHING""",
                            (token, row["id"], row["role"], expires)
                        )
                        conn.commit()
                    except Exception:
                        conn.rollback()

                    return self.send_json(200, {
                        "token": token,
                        "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
                        "message": "Login successful"
                    })
            except Exception as e:
                print("[LOGIN DB ERROR]", e)
                # Fall through to fallback
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # ── 2. Fallback store (DB unavailable) ────────────────────────────
        print("[LOGIN] Using fallback store (DB unavailable)")
        store = _load_fallback_store()
        matched = None
        for u in store.get("users", []):
            if u.get("username", "").lower() == username.lower():
                matched = u
                break

        if not matched or not verify_password(matched["password_hash"], matched["salt"], password):
            return self.send_json(401, {"error": "Invalid username or password"})

        role = matched.get("role", "user")
        if required_role and role != required_role:
            return self.send_json(401, {"error": "Invalid username or password"})

        token = create_session_token(matched["id"], matched["username"], role)
        return self.send_json(200, {
            "token": token,
            "user": {"id": matched["id"], "username": matched["username"], "role": role},
            "message": "Login successful"
        })
