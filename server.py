import http.server
import socketserver
import json
import sqlite3
import urllib.parse
import os

PORT = 8000
DB_FILE = "vault.db"

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt TEXT NOT NULL,
            data TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class VaultHandler(http.server.SimpleHTTPRequestHandler):
    
    def do_GET(self):
        if self.path == '/api/vault':
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('SELECT salt, data FROM vault WHERE id = 1')
            row = c.fetchone()
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            if row:
                try:
                    data_obj = json.loads(row[1])
                except Exception:
                    data_obj = row[1]
                response = {"salt": row[0], "data": data_obj}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.wfile.write(json.dumps({"error": "No vault found"}).encode())
        else:
            # Serve static files
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/vault':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            salt = data.get('salt')
            encrypted_data = data.get('data')
            
            if salt and encrypted_data:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('''
                    INSERT INTO vault (id, salt, data) VALUES (1, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, data=excluded.data
                ''', (salt, json.dumps(encrypted_data)))
                conn.commit()
                conn.close()
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith('/api/vault'):
            try:
                # Security: Check for ADMIN_KEY if configured in environment
                admin_key = os.environ.get('ADMIN_KEY')
                if admin_key:
                    client_key = self.headers.get('X-Admin-Key')
                    if not client_key:
                        parsed_url = urllib.parse.urlparse(self.path)
                        queries = urllib.parse.parse_qs(parsed_url.query)
                        client_key = queries.get('adminKey', [None])[0]
                    
                    if client_key != admin_key:
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Unauthorized: Invalid or missing Admin Key"}).encode())
                        return
                
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('DELETE FROM vault WHERE id = 1')
                conn.commit()
                conn.close()
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "deleted"}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

with socketserver.TCPServer(("", PORT), VaultHandler) as httpd:
    print(f"Serving VaultCore on port {PORT} with SQLite backend...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
