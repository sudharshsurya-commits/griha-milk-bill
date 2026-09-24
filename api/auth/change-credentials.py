import json
import secrets
from http.server import BaseHTTPRequestHandler
from api._db import (
    get_db,
    verify_password,
    hash_password,
    authenticate_request,
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
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        cur_pass = body.get("currentPassword", "").strip()
        new_user = body.get("newUsername", "").strip()
        new_pass = body.get("newPassword", "").strip()

        if not cur_pass:
            return self.send_json(400, {"error": "Current password is required"})

        if not new_user and not new_pass:
            return self.send_json(400, {"error": "Please provide a new username or new password"})

        if new_pass and len(new_pass) < 4:
            return self.send_json(400, {"error": "New password must be at least 4 characters long"})

        updated_username = user["username"]

        # 1. Primary: PostgreSQL
        conn = get_db()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT password_hash, salt FROM users WHERE id = %s", (user["id"],))
                    u_row = cur.fetchone()
                    if not u_row or not verify_password(u_row["password_hash"], u_row["salt"], cur_pass):
                        return self.send_json(400, {"error": "Incorrect current password"})

                    if new_user and new_user.lower() != user["username"].lower():
                        cur.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s) AND id != %s", (new_user, user["id"]))
                        if cur.fetchone():
                            return self.send_json(400, {"error": "Username already taken by another account"})
                        cur.execute("UPDATE users SET username = %s WHERE id = %s", (new_user, user["id"]))
                        updated_username = new_user

                    if new_pass:
                        new_salt = secrets.token_hex(16)
                        new_hash = hash_password(new_pass, new_salt)
                        cur.execute("UPDATE users SET password_hash = %s, salt = %s WHERE id = %s", (new_hash, new_salt, user["id"]))

                    conn.commit()
            except Exception as e:
                print("[CHANGE CREDS DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # 2. Resilient Fallback Store: always keep in sync
        store = _load_fallback_store()
        fallback_matched = None
        for u in store.get("users", []):
            if u["id"] == user["id"] or u["username"].lower() == user["username"].lower():
                fallback_matched = u
                break

        if fallback_matched:
            # If DB was not available, verify current password against fallback
            if not conn:
                if not verify_password(fallback_matched["password_hash"], fallback_matched["salt"], cur_pass):
                    return self.send_json(400, {"error": "Incorrect current password"})

            if new_user and new_user.lower() != user["username"].lower():
                fallback_matched["username"] = new_user
                updated_username = new_user

            if new_pass:
                new_salt = secrets.token_hex(16)
                fallback_matched["password_hash"] = hash_password(new_pass, new_salt)
                fallback_matched["salt"] = new_salt

            # Update username in active session
            token = user.get("token")
            if token and token in store.get("sessions", {}):
                store["sessions"][token]["username"] = updated_username

            _save_fallback_store(store)

        return self.send_json(200, {
            "message": "Credentials updated successfully",
            "newUsername": updated_username
        })
