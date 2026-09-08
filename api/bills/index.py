import json
import secrets
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler
from api.db import get_db, authenticate_request

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
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
                cur.execute("SELECT raw_data FROM bills WHERE user_id = %s ORDER BY created_at DESC", (user["id"],))
                rows = cur.fetchall()
                bills = []
                for r in rows:
                    try:
                        bills.append(json.loads(r["raw_data"]))
                    except Exception:
                        pass
                return self.send_json(200, {"bills": bills})
        except Exception as e:
            print("[GET BILLS ERROR]", e)
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
            bill = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            bill = {}

        b_id = str(bill.get("id") or secrets.token_hex(8))
        bill["id"] = b_id

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO bills (
                        id, user_id, cust_name, cust_phone, month, bill_no, bill_date,
                        total_days, hold_days, delivery_days, daily_qty, milk_unit, milk_rate, milk_amount,
                        items_json, items_total, receivable, payable, net_total, raw_data, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO UPDATE SET
                        cust_name = EXCLUDED.cust_name,
                        cust_phone = EXCLUDED.cust_phone,
                        month = EXCLUDED.month,
                        bill_no = EXCLUDED.bill_no,
                        bill_date = EXCLUDED.bill_date,
                        net_total = EXCLUDED.net_total,
                        raw_data = EXCLUDED.raw_data,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    b_id, user["id"],
                    bill.get("custName", ""), bill.get("custPhone", ""),
                    bill.get("month", ""), bill.get("billNo", ""), bill.get("billDate", ""),
                    int(bill.get("totalDays") or 0), int(bill.get("holdDays") or 0), int(bill.get("deliveryDays") or 0),
                    float(bill.get("dailyQty") or 0), str(bill.get("milkUnit") or ""),
                    float(bill.get("milkRate") or 0), float(bill.get("milkAmount") or 0),
                    json.dumps(bill.get("items") or []), float(bill.get("itemsTotal") or 0),
                    float(bill.get("receivable") or 0), float(bill.get("payable") or 0),
                    float(bill.get("netTotal") or 0),
                    json.dumps(bill)
                ))

                if bill.get("custName"):
                    cur.execute("""
                        INSERT INTO customers (user_id, name, phone, default_qty, default_unit, default_rate, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT(user_id, name) DO UPDATE SET
                            phone = COALESCE(EXCLUDED.phone, customers.phone),
                            default_qty = EXCLUDED.default_qty,
                            default_unit = EXCLUDED.default_unit,
                            default_rate = EXCLUDED.default_rate,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        user["id"], bill.get("custName"), bill.get("custPhone"),
                        float(bill.get("dailyQty") or 2), str(bill.get("milkUnit") or "Nazhi"), float(bill.get("milkRate") or 22)
                    ))

                conn.commit()
            return self.send_json(200, {"message": "Bill saved and synced to cloud", "id": b_id})
        except Exception as e:
            print("[SAVE BILL ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def do_DELETE(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        b_id = parts[-1] if len(parts) > 1 and parts[-1] != "bills" else ""

        if not b_id:
            return self.send_json(400, {"error": "Bill ID required for deletion"})

        conn = None
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM bills WHERE id = %s AND user_id = %s", (b_id, user["id"]))
                conn.commit()
            return self.send_json(200, {"message": "Bill deleted from cloud", "id": b_id})
        except Exception as e:
            print("[DELETE BILL ERROR]", e)
            return self.send_json(500, {"error": "Database error", "details": str(e)})
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
