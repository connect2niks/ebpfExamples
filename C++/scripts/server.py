from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        print("\n──────── REQUEST ────────")
        print(f"Path: {self.path}")
        
        # ── Print all headers ──
        print("Headers:")
        for key, val in self.headers.items():
            print(f"  {key}: {val}")

        # ── Print body ──
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)
        print(f"Body: {body.decode()}")
        print("─────────────────────────\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()