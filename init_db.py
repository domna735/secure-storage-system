import os
import sqlite3
from client_functions import hash_password, encrypt_key

def init_db():
    """ Initialise the database and create the necessary tables (chunked storage is supported) """
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()

    # ✅ User table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            mfa_secret TEXT
        )
    ''')

    # ✅ File table：Used to record file_id for Chunk table reference
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            filename TEXT,
            FOREIGN KEY(owner) REFERENCES users(username),
            UNIQUE(owner, filename)
        )
    ''')

    # ✅ Chunk table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_chunks (
            file_id INTEGER,
            chunk_index INTEGER,
            encrypted_data BLOB,
            iv TEXT,
            PRIMARY KEY (file_id, chunk_index),
            FOREIGN KEY(file_id) REFERENCES files(file_id)
        )
    ''')

    # ✅ File sharing table (supports owner + filename → recipient)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            owner TEXT,
            filename TEXT,
            recipient TEXT,
            PRIMARY KEY (owner, filename, recipient),
            FOREIGN KEY(owner) REFERENCES users(username),
            FOREIGN KEY(recipient) REFERENCES users(username)
        )
    ''')

    # ✅ Log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT
        )
    ''')

    # ✅ Initialise the administrator account admin
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if cursor.fetchone() is None:
        default_password = "admin123"
        password_hash = hash_password(default_password)
        aes_key = os.urandom(32)
        encrypted_key = encrypt_key(aes_key)
        cursor.execute("INSERT INTO users (username, password_hash, encrypted_key) VALUES (?, ?, ?)",
                       ('admin', password_hash, encrypted_key))
        print("🛠 Admin account created with default username: admin & password: admin123")

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully with full chunked file support.")

if __name__ == "__main__":
    init_db()
