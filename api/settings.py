import json
from http.server import BaseHTTPRequestHandler
from api._db import get_db, authenticate_request, _load_fallback_store, _save_fallback_store

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

        conn = get_db()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM settings WHERE user_id = %s", (user["id"],))
                    row = cur.fetchone()
                    if row:
                        s_data = dict(row)
                        for k, v in list(s_data.items()):
                            if hasattr(v, '__float__'):
                                s_data[k] = float(v)
                            elif hasattr(v, 'isoformat'):
                                s_data[k] = v.isoformat()
                        return self.send_json(200, {"settings": s_data})
            except Exception as e:
                print("[GET SETTINGS DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        store = _load_fallback_store()
        u_settings = store.get("settings", {}).get(str(user["id"]), {})
        return self.send_json(200, {"settings": u_settings})

    def do_POST(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        # Save to fallback store
        store = _load_fallback_store()
        user_settings_dict = store.setdefault("settings", {})
        user_settings_dict[str(user["id"])] = body
        _save_fallback_store(store)

        conn = get_db()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO settings (user_id, brand_name, tagline, care_no, default_rate, upi_id, logo_data, qr_data, layout_data, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT(user_id) DO UPDATE SET
                            brand_name = EXCLUDED.brand_name,
                            tagline = EXCLUDED.tagline,
                            care_no = EXCLUDED.care_no,
                            default_rate = EXCLUDED.default_rate,
                            upi_id = EXCLUDED.upi_id,
                            logo_data = EXCLUDED.logo_data,
                            qr_data = EXCLUDED.qr_data,
                            layout_data = EXCLUDED.layout_data,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        user["id"],
                        body.get("brand_name", "GRIHA"),
                        body.get("tagline", "Feel The Quality"),
                        body.get("care_no", "+91 99999 99999"),
                        float(body.get("default_rate") or 22),
                        body.get("upi_id", "griha@upi"),
                        body.get("logo_data"),
                        body.get("qr_data"),
                        json.dumps(body.get("layout_data")) if isinstance(body.get("layout_data"), (dict, list)) else body.get("layout_data")
                    ))
                    conn.commit()
            except Exception as e:
                print("[SAVE SETTINGS DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        return self.send_json(200, {"message": "Settings saved successfully"})
