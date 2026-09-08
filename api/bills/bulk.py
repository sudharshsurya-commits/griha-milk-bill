import json
import secrets
from http.server import BaseHTTPRequestHandler
from api._db import get_db, authenticate_request

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
            data = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            data = {}

        bills = data.get("bills", [])
        saved_count = 0

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                for bill in bills:
                    b_id = str(bill.get("id") or secrets.token_hex(8))
                    bill["id"] = b_id
                    cur.execute("""
                        INSERT INTO bills (
                            id, user_id, cust_name, cust_phone, month, bill_no, bill_date,
                            net_total, raw_data, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT(id) DO UPDATE SET
                            cust_name = EXCLUDED.cust_name,
                            cust_phone = EXCLUDED.cust_phone,
                            month = EXCLUDED.month,
                            net_total = EXCLUDED.net_total,
                            raw_data = EXCLUDED.raw_data,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        b_id, user["id"],
                        bill.get("custName", ""), bill.get("custPhone", ""),
                        bill.get("month", ""), bill.get("billNo", ""), bill.get("billDate", ""),
                        float(bill.get("netTotal") or 0), json.dumps(bill)
                    ))
                    saved_count += 1
                conn.commit()

            return self.send_json(200, {"message": f"{saved_count} bills saved and synced to cloud", "count": saved_count})
        except Exception as e:
            print("[BULK BILLS ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
