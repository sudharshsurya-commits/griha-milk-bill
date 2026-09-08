import json
from http.server import BaseHTTPRequestHandler
from api.db import get_db, authenticate_request

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

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM settings WHERE user_id = %s", (user["id"],))
                row = cur.fetchone()
                if row:
                    return self.send_json(200, {
                        "brandName": row["brand_name"],
                        "tagline": row["tagline"],
                        "careNo": row["care_no"],
                        "defaultRate": float(row["default_rate"]) if row["default_rate"] is not None else 22,
                        "upiId": row["upi_id"],
                        "qrMode": row["qr_mode"],
                        "logoSrc": row["logo_data"],
                        "uploadedQrSrc": row["qr_data"],
                        "layoutSettings": json.loads(row["layout_data"]) if row["layout_data"] else None
                    })
                return self.send_json(200, {})
        except Exception as e:
            print("[GET SETTINGS ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def do_POST(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            data = {}

        b_name = data.get("brandName", "GRIHA")
        tagline = data.get("tagline", "Feel The Quality")
        care_no = data.get("careNo", "+91 99999 99999")
        rate = float(data.get("defaultRate", 22))
        upi_id = data.get("upiId", "")
        qr_mode = data.get("qrMode", "generated")
        logo_src = data.get("logoSrc", None)
        qr_src = data.get("uploadedQrSrc", None)
        layout_data = json.dumps(data.get("layoutSettings")) if data.get("layoutSettings") else None

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO settings (user_id, brand_name, tagline, care_no, default_rate, upi_id, qr_mode, logo_data, qr_data, layout_data, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(user_id) DO UPDATE SET
                        brand_name = EXCLUDED.brand_name,
                        tagline = EXCLUDED.tagline,
                        care_no = EXCLUDED.care_no,
                        default_rate = EXCLUDED.default_rate,
                        upi_id = EXCLUDED.upi_id,
                        qr_mode = EXCLUDED.qr_mode,
                        logo_data = COALESCE(EXCLUDED.logo_data, settings.logo_data),
                        qr_data = COALESCE(EXCLUDED.qr_data, settings.qr_data),
                        layout_data = COALESCE(EXCLUDED.layout_data, settings.layout_data),
                        updated_at = CURRENT_TIMESTAMP
                """, (user["id"], b_name, tagline, care_no, rate, upi_id, qr_mode, logo_src, qr_src, layout_data))
                conn.commit()

            return self.send_json(200, {"message": "Settings synced successfully"})
        except Exception as e:
            print("[SAVE SETTINGS ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
