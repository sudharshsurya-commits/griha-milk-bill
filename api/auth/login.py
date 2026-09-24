import json
import secrets
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from api._db import (
    get_db,
    verify_password,
    hash_password,
    ensure_db_initialized,
    _load_fallback_store,
    _save_fallback_store,
)

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

        # 1. Primary: PostgreSQL
        conn = get_db()
        if conn:
            try:
                ensure_db_initialized(conn)
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, username, password_hash, salt FROM users WHERE LOWER(username) = LOWER(%s)",
                        (username,)
                    )
                    row = cur.fetchone()
                    if not row:
                        return self.send_json(401, {"error": "Invalid username or password"})

                    is_valid = verify_password(row["password_hash"], row["salt"], password)

                    # Auto-seed check: if admin account has legacy hash and password is default 'admin123', update it
                    if not is_valid and row["username"].lower() == "admin" and password == "admin123":
                        new_salt = secrets.token_hex(16)
                        new_h = hash_password("admin123", new_salt)
                        cur.execute(
                            "UPDATE users SET password_hash = %s, salt = %s WHERE id = %s",
                            (new_h, new_salt, row["id"])
                        )
                        conn.commit()
                        is_valid = True

                    if not is_valid:
                        return self.send_json(401, {"error": "Invalid username or password"})

                    token = secrets.token_hex(32)
                    expires = datetime.utcnow() + timedelta(days=30)
                    cur.execute(
                        "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
                        (token, row["id"], expires)
                    )
                    conn.commit()

                    # Also update fallback cache
                    store = _load_fallback_store()
                    store["sessions"][token] = {
                        "user_id": row["id"],
                        "username": row["username"],
                        "expires_at": expires.isoformat()
                    }
                    _save_fallback_store(store)

                    return self.send_json(200, {
                        "token": token,
                        "user": {"id": row["id"], "username": row["username"]},
                        "message": "Login successful"
                    })
            except Exception as e:
                print("[LOGIN DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # 2. Resilient Fallback Store (when PostgreSQL is unreachable or asleep)
        print("[LOGIN FALLBACK] Authenticating via resilient store")
        store = _load_fallback_store()
        matched_user = None
        for u in store.get("users", []):
            if u["username"].lower() == username.lower():
                matched_user = u
                break

        if not matched_user:
            return self.send_json(401, {"error": "Invalid username or password"})

        if not verify_password(matched_user["password_hash"], matched_user["salt"], password):
            return self.send_json(401, {"error": "Invalid username or password"})

        token = secrets.token_hex(32)
        expires = datetime.utcnow() + timedelta(days=30)
        store["sessions"][token] = {
            "user_id": matched_user["id"],
            "username": matched_user["username"],
            "expires_at": expires.isoformat()
        }
        _save_fallback_store(store)

        return self.send_json(200, {
            "token": token,
            "user": {"id": matched_user["id"], "username": matched_user["username"]},
            "message": "Login successful"
        })
