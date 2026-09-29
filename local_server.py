"""
Local development server for GRIHA Milk Bill Generator.
Serves static files (bill_generator.html, admin.html, sw.js, manifest.json, assets)
and handles /api/* routes using the serverless handlers.
"""
import os
import sys
import json
import traceback
import urllib.parse
import importlib
from http.server import HTTPServer, SimpleHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

change_credentials_mod = importlib.import_module("api.auth.change-credentials")
ChangeCredsHandler = change_credentials_mod.handler

change_user_mod = importlib.import_module("api.auth.change-user")
ChangeUserHandler = change_user_mod.handler

from api.auth.login import handler as LoginHandler
from api.auth.me import handler as MeHandler
from api.auth.logout import handler as LogoutHandler
from api.health import handler as HealthHandler
from api.settings import handler as SettingsHandler
from api.customers import handler as CustomersHandler
from api.bills.index import handler as BillsIndexHandler
from api.bills.bulk import handler as BillsBulkHandler

class LocalAppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PROJECT_ROOT, **kwargs)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            self.send_response(204)
            self._cors_headers()
            self.end_headers()
        else:
            super().do_OPTIONS()

    def do_GET(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/" or path == "/bill_generator.html":
                self.path = "/bill_generator.html"
                return super().do_GET()
            elif path == "/admin" or path == "/admin.html":
                self.path = "/admin.html"
                return super().do_GET()
            elif path == "/api/health":
                return HealthHandler.do_GET(self)
            elif path == "/api/auth/me":
                return MeHandler.do_GET(self)
            elif path.startswith("/api/bills/bulk"):
                return BillsBulkHandler.do_GET(self)
            elif path.startswith("/api/bills"):
                return BillsIndexHandler.do_GET(self)
            elif path == "/api/settings":
                return SettingsHandler.do_GET(self)
            elif path == "/api/customers":
                return CustomersHandler.do_GET(self)
            elif path.startswith("/api/"):
                return self.send_json(404, {"error": "API route not found"})
            else:
                return super().do_GET()
        except Exception as e:
            print("[SERVER GET ERROR]", e)
            traceback.print_exc()

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/auth/login":
                return LoginHandler.do_POST(self)
            elif path == "/api/auth/logout":
                return LogoutHandler.do_POST(self)
            elif path == "/api/auth/change-credentials":
                return ChangeCredsHandler.do_POST(self)
            elif path == "/api/auth/change-user":
                return ChangeUserHandler.do_POST(self)
            elif path == "/api/settings":
                return SettingsHandler.do_POST(self)
            elif path == "/api/customers":
                return CustomersHandler.do_POST(self)
            elif path.startswith("/api/bills/bulk"):
                return BillsBulkHandler.do_POST(self)
            elif path.startswith("/api/bills"):
                return BillsIndexHandler.do_POST(self)
            else:
                return self.send_json(404, {"error": "API route not found"})
        except Exception as e:
            print("[SERVER POST ERROR]", e)
            traceback.print_exc()

    def do_DELETE(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/bills"):
                return BillsIndexHandler.do_DELETE(self)
            else:
                return self.send_json(404, {"error": "API route not found"})
        except Exception as e:
            print("[SERVER DELETE ERROR]", e)
            traceback.print_exc()

def run(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, LocalAppHandler)
    print(f"GRIHA Milk Bill Local Server running at http://localhost:{port}/")
    print(f"  * Bill Generator: http://localhost:{port}/")
    print(f"  * Admin Panel:    http://localhost:{port}/admin")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == '__main__':
    port = 8000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run(port)
