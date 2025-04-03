import os
import sqlite3
from client_functions import hash_password, encrypt_key

def init_db():
    """ 初始化数据库，创建必要的表（支持分块存储） """
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()

    # ✅ 用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            encrypted_key TEXT
        )
    ''')

    # ✅ 文件表：用于记录 file_id，供 chunk 表引用
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            filename TEXT,
            FOREIGN KEY(owner) REFERENCES users(username),
            UNIQUE(owner, filename)
        )
    ''')

    # ✅ 分块存储表
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

    # ✅ 文件共享表（支持 owner + filename → recipient）
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

    # ✅ 日志表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT
        )
    ''')

    # ✅ 初始化管理员账户 admin
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if cursor.fetchone() is None:
        default_password = "admin123"
        password_hash = hash_password(default_password)
        aes_key = os.urandom(32)
        encrypted_key = encrypt_key(aes_key)
        cursor.execute("INSERT INTO users (username, password_hash, encrypted_key) VALUES (?, ?, ?)",
                       ('admin', password_hash, encrypted_key))
        print("🛠 Admin account created with default password: admin123")

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully with full chunked file support.")

if __name__ == "__main__":
    init_db()
