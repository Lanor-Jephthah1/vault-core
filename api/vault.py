import json
import sqlite3
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler

DB_FILE = "vault.db"

def get_db_connection():
    db_url = os.environ.get('DATABASE_URL')
    if db_url:
        # PostgreSQL
        import pg8000.dbapi
        
        # Parse database url
        # Sometimes connection strings use postgresql://, pg8000 is fine with it
        url = urllib.parse.urlparse(db_url)
        username = url.username
        password = url.password
        database = url.path[1:]
        hostname = url.hostname
        port = url.port or 5432
        
        conn = pg8000.dbapi.connect(
            user=username,
            password=password,
            host=hostname,
            port=port,
            database=database
        )
        return conn, True
    else:
        # SQLite fallback
        conn = sqlite3.connect(DB_FILE)
        return conn, False

def init_db():
    try:
        conn, is_postgres = get_db_connection()
        c = conn.cursor()
        if is_postgres:
            c.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY,
                    salt TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            ''')
        else:
            c.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error initializing DB: {e}")

# Initialize on startup
init_db()

class handler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        if self.path.startswith('/api/vault'):
            try:
                conn, is_postgres = get_db_connection()
                c = conn.cursor()
                
                # SQLite and pg8000 both support fetchone/fetchmany
                # But pg8000 returns list of lists, SQLite returns list of tuples
                c.execute('SELECT salt, data FROM vault WHERE id = 1')
                row = c.fetchone()
                conn.close()
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                
                if row:
                    salt_val = row[0]
                    data_val = row[1]
                    
                    # If postgres/sqlite returns a string, try to parse it
                    try:
                        data_obj = json.loads(data_val)
                    except Exception:
                        data_obj = data_val
                        
                    response = {"salt": salt_val, "data": data_obj}
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.wfile.write(json.dumps({"error": "No vault found"}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/vault'):
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                salt = data.get('salt')
                encrypted_data = data.get('data')
                
                if salt and encrypted_data:
                    conn, is_postgres = get_db_connection()
                    c = conn.cursor()
                    
                    placeholder = '%s' if is_postgres else '?'
                    query = f'''
                        INSERT INTO vault (id, salt, data) VALUES (1, {placeholder}, {placeholder})
                        ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, data=excluded.data
                    '''
                    
                    c.execute(query, (salt, json.dumps(encrypted_data)))
                    conn.commit()
                    conn.close()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "success"}).encode())
                else:
                    self.send_response(400)
                    self.end_headers()
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
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
                
                conn, is_postgres = get_db_connection()
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
