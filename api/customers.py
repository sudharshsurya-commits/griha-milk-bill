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
                    cur.execute("SELECT * FROM customers WHERE user_id = %s ORDER BY name ASC", (user["id"],))
                    rows = cur.fetchall()
                    customers = []
                    for r in rows:
                        c_dict = dict(r)
                        for k, v in list(c_dict.items()):
                            if hasattr(v, '__float__'):
                                c_dict[k] = float(v)
                            elif hasattr(v, 'isoformat'):
                                c_dict[k] = v.isoformat()
                        customers.append(c_dict)
                    return self.send_json(200, {"customers": customers})
            except Exception as e:
                print("[GET CUSTOMERS DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        store = _load_fallback_store()
        u_customers = store.get("customers", {}).get(str(user["id"]), [])
        return self.send_json(200, {"customers": u_customers})

    def do_POST(self):
        user = authenticate_request(self.headers)
        if not user:
            return self.send_json(401, {"error": "Authentication required"})

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        except Exception:
            body = {}

        name = (body.get("name") or "").strip()
        if not name:
            return self.send_json(400, {"error": "Customer name is required"})

        # Save to fallback store
        store = _load_fallback_store()
        user_cust_dict = store.setdefault("customers", {})
        uc_list = user_cust_dict.setdefault(str(user["id"]), [])
        # Upsert
        found = False
        for idx, c in enumerate(uc_list):
            if c.get("name", "").lower() == name.lower():
                uc_list[idx] = body
                found = True
                break
        if not found:
            uc_list.append(body)
        _save_fallback_store(store)

        conn = get_db()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO customers (user_id, name, phone, default_qty, default_unit, default_rate, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT(user_id, name) DO UPDATE SET
                            phone = EXCLUDED.phone,
                            default_qty = EXCLUDED.default_qty,
                            default_unit = EXCLUDED.default_unit,
                            default_rate = EXCLUDED.default_rate,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        user["id"], name, body.get("phone", ""),
                        float(body.get("default_qty") or 2), str(body.get("default_unit") or "Nazhi"), float(body.get("default_rate") or 22)
                    ))
                    conn.commit()
            except Exception as e:
                print("[SAVE CUSTOMER DB ERROR]", e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        return self.send_json(200, {"message": "Customer saved successfully"})
