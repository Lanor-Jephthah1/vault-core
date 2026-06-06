import csv
import json
import sqlite3
import base64
import os
import getpass
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

DB_FILE = "vault.db"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_data(key: bytes, plaintext: str) -> dict:
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    cipher_text = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    return {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "cipherText": base64.b64encode(cipher_text).decode('utf-8')
    }

def decrypt_data(key: bytes, iv_b64: str, cipher_b64: str) -> str:
    aesgcm = AESGCM(key)
    iv = base64.b64decode(iv_b64)
    cipher_text = base64.b64decode(cipher_b64)
    plaintext = aesgcm.decrypt(iv, cipher_text, None)
    return plaintext.decode('utf-8')

def main():
    if len(sys.argv) < 2:
        print("Usage: python import_csv.py <path_to_csv>")
        sys.exit(1)
        
    csv_file = sys.argv[1]
    if not os.path.exists(csv_file):
        print(f"File not found: {csv_file}")
        sys.exit(1)

    password = getpass.getpass("Enter your VaultCore Master Password: ")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY CHECK (id = 1), salt TEXT NOT NULL, data TEXT NOT NULL)')
    
    c.execute('SELECT salt, data FROM vault WHERE id = 1')
    row = c.fetchone()
    
    existing_entries = []
    
    if row:
        salt_b64 = row[0]
        data_json = json.loads(row[1])
        salt = base64.b64decode(salt_b64)
        key = derive_key(password, salt)
        try:
            decrypted_str = decrypt_data(key, data_json['iv'], data_json['cipherText'])
            existing_entries = json.loads(decrypted_str)
            print(f"Successfully decrypted vault. Found {len(existing_entries)} existing entries.")
        except Exception as e:
            print("Failed to decrypt the vault. Incorrect master password or corrupted data.")
            sys.exit(1)
    else:
        print("No existing vault found. Creating a new one.")
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        key = derive_key(password, salt)

    # Read CSV
    new_entries = []
    try:
        with open(csv_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Make columns case-insensitive
            reader.fieldnames = [name.lower().strip() for name in reader.fieldnames]
            
            for row in reader:
                raw_name = row.get('name', '')
                raw_url = row.get('url', '')
                
                final_name = raw_name
                if raw_url and raw_url not in raw_name:
                    final_name = f"{raw_name} ({raw_url})" if raw_name else raw_url
                
                if not final_name and not row.get('username') and not row.get('password'):
                    continue
                    
                entry = {
                    "name": final_name or "Imported Entry",
                    "username": row.get('username', ''),
                    "password": row.get('password', ''),
                    "category": "login",
                    "cardholder": "",
                    "expiry": "",
                    "pwned": None
                }
                new_entries.append(entry)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    print(f"Found {len(new_entries)} entries in CSV.")
    if len(new_entries) == 0:
        print("Nothing to import.")
        sys.exit(0)
        
    all_entries = existing_entries + new_entries
    
    encrypted_obj = encrypt_data(key, json.dumps(all_entries))
    
    c.execute('''
        INSERT INTO vault (id, salt, data) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, data=excluded.data
    ''', (salt_b64, json.dumps(encrypted_obj)))
    conn.commit()
    conn.close()
    
    print(f"Successfully imported {len(new_entries)} passwords! Total passwords in vault: {len(all_entries)}")

if __name__ == "__main__":
    main()
