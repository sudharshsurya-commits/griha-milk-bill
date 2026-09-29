"""
Admin-only: Change normal user account credentials (username and/or password).
Only an authenticated admin can call this. Normal users cannot change their own credentials.
"""
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

    def do_POST(self):
        # Must be an authenticated admin
        admin = authenticate_request(self.headers, required_role="admin")
        if not admin:
            return self.send_json(401, {"error": "Admin access required"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        cur_user_pass = (body.get("currentUserPassword") or "").strip()
        new_user_name = (body.get("newUsername") or "").strip()
        new_user_pass = (body.get("newPassword") or "").strip()

        if not cur_user_pass:
            return self.send_json(400, {"error": "Current user password is required to verify"})
        if not new_user_name and not new_user_pass:
            return self.send_json(400, {"error": "Please provide a new username or new password"})
        if new_user_pass and len(new_user_pass) < 4:
            return self.send_json(400, {"error": "New password must be at least 4 characters"})

        updated_username = None
        db_updated = False

        # ── 1. Primary: PostgreSQL ─────────────────────────────────────────
        conn = get_db()
        if conn:
            try:
                with conn.cursor() as cur:
                    # Find the normal user account
                    cur.execute(
                        "SELECT id, username, password_hash, salt FROM users WHERE role = 'user' LIMIT 1"
                    )
                    target = cur.fetchone()
                    if not target:
                        return self.send_json(404, {"error": "No normal user account found in database"})

                    if not verify_password(target["password_hash"], target["salt"], cur_user_pass):
                        return self.send_json(400, {"error": "Incorrect current user password"})

                    updated_username = target["username"]

                    if new_user_name and new_user_name.lower() != target["username"].lower():
                        cur.execute(
                            "SELECT id FROM users WHERE LOWER(username) = LOWER(%s) AND id != %s",
                            (new_user_name, target["id"])
                        )
                        if cur.fetchone():
                            return self.send_json(400, {"error": "Username is already taken"})
                        cur.execute("UPDATE users SET username = %s WHERE id = %s", (new_user_name, target["id"]))
                        updated_username = new_user_name

                    if new_user_pass:
                        new_salt = secrets.token_hex(16)
                        new_hash = hash_password(new_user_pass, new_salt)
                        cur.execute(
                            "UPDATE users SET password_hash = %s, salt = %s WHERE id = %s",
                            (new_hash, new_salt, target["id"])
                        )

                    # Invalidate all sessions for this user
                    cur.execute("DELETE FROM sessions WHERE user_id = %s AND role = 'user'", (target["id"],))
                    conn.commit()
                    db_updated = True
            except Exception as e:
                print("[CHANGE USER CREDS DB ERROR]", e)
                try:
                    conn.rollback()
                except Exception:
                    pass
                return self.send_json(500, {"error": "Unable to complete the request. Please try again."})
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # ── 2. Fallback store sync ─────────────────────────────────────────
        store = _load_fallback_store()
        target_fallback = None
        for u in store.get("users", []):
            if u.get("role") == "user":
                target_fallback = u
                break

        if not db_updated:
            if not target_fallback:
                return self.send_json(404, {"error": "No normal user account found"})
            if not verify_password(target_fallback["password_hash"], target_fallback["salt"], cur_user_pass):
                return self.send_json(400, {"error": "Incorrect current user password"})

        if target_fallback:
            updated_username = updated_username or target_fallback["username"]
            if new_user_name:
                target_fallback["username"] = new_user_name
                updated_username = new_user_name
            if new_user_pass:
                s = secrets.token_hex(16)
                target_fallback["password_hash"] = hash_password(new_user_pass, s)
                target_fallback["salt"] = s
            _save_fallback_store(store)

        return self.send_json(200, {
            "message": "Normal user credentials updated successfully",
            "newUsername": updated_username or "user"
        })
