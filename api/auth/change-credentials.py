import json
import secrets
from http.server import BaseHTTPRequestHandler
from api.db import get_db, verify_password, hash_password, authenticate_request

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

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash, salt FROM users WHERE id = %s", (user["id"],))
                u_row = cur.fetchone()
                if not u_row or not verify_password(u_row["password_hash"], u_row["salt"], cur_pass):
                    return self.send_json(400, {"error": "Incorrect current password"})

                if new_user and new_user.lower() != user["username"].lower():
                    cur.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_user, user["id"]))
                    if cur.fetchone():
                        return self.send_json(400, {"error": "Username already taken by another account"})
                    cur.execute("UPDATE users SET username = %s WHERE id = %s", (new_user, user["id"]))

                if new_pass:
                    new_salt = secrets.token_hex(16)
                    new_hash = hash_password(new_pass, new_salt)
                    cur.execute("UPDATE users SET password_hash = %s, salt = %s WHERE id = %s", (new_hash, new_salt, user["id"]))

                conn.commit()
                return self.send_json(200, {
                    "message": "Credentials updated successfully",
                    "newUsername": new_user or user["username"]
                })
        except Exception as e:
            print("[CHANGE CREDS ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
