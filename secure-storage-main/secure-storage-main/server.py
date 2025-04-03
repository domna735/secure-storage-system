import base64
import hashlib
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# 连接数据库
def get_db_connection():
    return sqlite3.connect('secure_storage.db', check_same_thread=False)

# 记录日志的函数
def log_action(username, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (username, action) VALUES (?, ?)", (username, action))
    conn.commit()
    conn.close()

# 检查函数
def is_valid_filename(filename):
    return filename and ".." not in filename and not filename.startswith("/") and not filename.startswith("\\")

# **存储哈希**
@app.route('/get_hash', methods=['POST'])
def get_hash():
    data = request.json
    username = data.get("username")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({"password_hash": result[0]}), 200
    else:
        return jsonify({"error": "User not found."}), 400

# **用户注册**
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password_hash = data.get("password_hash")
    encrypted_key = data.get("encrypted_key")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash, encrypted_key) VALUES (?, ?, ?)", 
                       (username, password_hash, encrypted_key))
        conn.commit()
        # 记录日志
        log_action(username, "User registered")
        return jsonify({"message": "User registered successfully"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

# **登录验证（Server 只存储哈希，不解密密码）**
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password_hash = data.get("password_hash")

    if not username or not password_hash:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, encrypted_key FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result and result[0] == password_hash:
        # 记录日志
        log_action(username, "User logged in")
        return jsonify({"message": "Login successful", "encrypted_key": result[1]}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 400

# **修改密码**
@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    username = data.get("username")
    new_password_hash = data.get("new_password_hash")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Password changed successfully."}), 200





@app.route('/logs', methods=['GET'])
def view_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, username, action FROM logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()

    return jsonify({
        "logs": [
            {"timestamp": t, "username": u, "action": a}
            for t, u, a in logs
        ]
    }), 200


# expended
# 分块上传
@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")
    chunk_index = data.get("chunk_index")
    encrypted_data = data.get("encrypted_data")
    iv = data.get("iv")

    if not all([username, filename, chunk_index is not None, encrypted_data, iv]):
        return jsonify({"error": "Missing required fields"}), 400

    if not is_valid_filename(filename):
        return jsonify({"error": "Invalid filename"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 如果文件在 files 表中不存在，插入一条文件记录
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    file_row = cursor.fetchone()

    if not file_row:
        cursor.execute("INSERT INTO files (owner, filename) VALUES (?, ?)", (username, filename))
        file_id = cursor.lastrowid
    else:
        file_id = file_row[0]

    # 判断当前块是否已存在（避免重复上传）
    cursor.execute("SELECT 1 FROM file_chunks WHERE file_id=? AND chunk_index=?", (file_id, chunk_index))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": f"Chunk {chunk_index} already uploaded"}), 400

    # 插入 chunk
    cursor.execute(
        "INSERT INTO file_chunks (file_id, chunk_index, encrypted_data, iv) VALUES (?, ?, ?, ?)",
        (file_id, chunk_index, encrypted_data, iv)
    )

    conn.commit()
    conn.close()

    log_action(username, f"Uploaded chunk {chunk_index} of file {filename}")
    return jsonify({"message": f"Chunk {chunk_index} uploaded successfully"}), 200

# 断点续传
@app.route('/check_uploaded_chunks', methods=['POST'])
def check_uploaded_chunks():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")
    chunk_hashes = data.get("chunk_hashes")  # ✨ 来自客户端

    if not username or not filename or not chunk_hashes:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    row = cursor.fetchone()

    if not row:
        return jsonify({"missing_chunks": list(range(len(chunk_hashes)))}), 200

    file_id = row[0]
    cursor.execute("SELECT chunk_index, encrypted_data FROM file_chunks WHERE file_id=?", (file_id,))
    existing_chunks = cursor.fetchall()
    conn.close()

    # ✨ 服务器重新计算已上传块的哈希
    existing_hashes = {}
    for idx, enc_data in existing_chunks:
        try:
            decoded_data = base64.b64decode(enc_data)
            h = hashlib.sha256(decoded_data).hexdigest()
            existing_hashes[idx] = h
        except:
            continue

    missing = []
    for i, h in enumerate(chunk_hashes):
        if existing_hashes.get(i) != h:
            missing.append(i)

    return jsonify({"missing_chunks": missing}), 200


# 下载
@app.route('/download_chunks', methods=['GET'])
def download_chunks():
    username = request.args.get("username")
    filename = request.args.get("filename")

    if not username or not filename:
        return jsonify({"error": "Missing parameters"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    file_id = None
    owner = None

    # ✅ 尝试作为 owner 下载
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    row = cursor.fetchone()
    if row:
        file_id = row[0]
        owner = username
    else:
        # ✅ 尝试作为被共享者下载
        cursor.execute("""
            SELECT f.file_id, f.owner
            FROM shared_files sf
            JOIN files f ON sf.owner = f.owner AND sf.filename = f.filename
            WHERE sf.recipient=? AND sf.filename=?
        """, (username, filename))
        row = cursor.fetchone()
        if row:
            file_id, owner = row  # 注意此时 owner ≠ username

    if file_id is None:
        conn.close()
        return jsonify({"error": "File not found or not accessible"}), 404

    # 获取 chunk 信息
    cursor.execute("SELECT chunk_index, encrypted_data, iv FROM file_chunks WHERE file_id=? ORDER BY chunk_index ASC", (file_id,))
    chunks_raw = cursor.fetchall()

    # 检查是否需要重加密（即被共享者）
    if owner != username:
        # 获取 owner 和 recipient 的加密 AES key
        cursor.execute("SELECT encrypted_key FROM users WHERE username=?", (owner,))
        owner_encrypted_key = cursor.fetchone()[0]

        cursor.execute("SELECT encrypted_key FROM users WHERE username=?", (username,))
        recipient_encrypted_key = cursor.fetchone()[0]

        from client_functions import decrypt_key, encrypt_data,decrypt_data  # ✅ 确保你有这些函数
        from base64 import b64encode, b64decode

        owner_key = decrypt_key(owner_encrypted_key)          # 使用 Master Key 解密 owner 的 AES key
        recipient_key = decrypt_key(recipient_encrypted_key)  # 使用 Master Key 解密 recipient 的 AES key

        chunks = []
        for idx, enc_data, iv in chunks_raw:
            try:
                raw_data = decrypt_data(b64decode(enc_data), owner_key, b64decode(iv))
                re_enc, re_iv = encrypt_data(raw_data, recipient_key)
                chunks.append({
                    "chunk_index": idx,
                    "encrypted_data": b64encode(re_enc).decode(),
                    "iv": b64encode(re_iv).decode()
                })
            except Exception as e:
                conn.close()
                return jsonify({"error": f"Chunk {idx} re-encryption failed: {str(e)}"}), 500
    else:
        # 自己访问，直接原样返回
        chunks = [
            {"chunk_index": idx, "encrypted_data": data, "iv": iv}
            for idx, data, iv in chunks_raw
        ]

    conn.close()
    return jsonify({"chunks": chunks}), 200



# 删除分块文件
@app.route('/delete_chunks', methods=['POST'])
def delete_chunks():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")

    if not username or not filename:
        return jsonify({"error": "Missing parameters"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 找到文件 ID
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    file_id = row[0]

    # 删除文件块
    cursor.execute("DELETE FROM file_chunks WHERE file_id=?", (file_id,))
    # 删除文件记录
    cursor.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    # 删除共享记录
    cursor.execute("DELETE FROM shared_files WHERE owner=? AND filename=?", (username, filename))

    conn.commit()
    conn.close()

    log_action(username, f"Deleted file '{filename}' and related shares.")
    return jsonify({"message": f"File '{filename}' deleted successfully."}), 200


# 共享
@app.route('/share', methods=['POST'])
def share():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")
    recipient = data.get("recipient")

    if not is_valid_filename(filename):
        return jsonify({"error": "Invalid filename"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 检查接收者是否存在
    cursor.execute("SELECT 1 FROM users WHERE username=?", (recipient,))
    if not cursor.fetchone():
        return jsonify({"error": "Recipient user does not exist"}), 400

    # ✅ 正确：从 files 表中检查文件所有权
    cursor.execute("SELECT 1 FROM files WHERE owner=? AND filename=? LIMIT 1", (username, filename))
    if not cursor.fetchone():
        return jsonify({"error": "File not found or not owned by user"}), 400

    # 插入共享记录
    try:
        cursor.execute("INSERT INTO shared_files (owner, filename, recipient) VALUES (?, ?, ?)",
                       (username, filename, recipient))
        conn.commit()
        log_action(username, f"File {filename} shared with {recipient}")
        return jsonify({"message": "File shared successfully"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "This file is already shared with the user"}), 400
    finally:
        conn.close()


# 列举
@app.route('/list_files', methods=['GET'])
def list_files():
    username = request.args.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 自己拥有的文件
    cursor.execute("SELECT filename FROM files WHERE owner=?", (username,))
    own_files = {row[0] for row in cursor.fetchall()}

    # 共享给用户的文件
    cursor.execute("SELECT filename FROM shared_files WHERE recipient=?", (username,))
    shared_files = {row[0] for row in cursor.fetchall()}

    conn.close()

    all_files = sorted(own_files.union(shared_files))

    # ✅ 只返回一次，确保 JSON 不被污染
    return jsonify({"files": all_files}), 200



# 运行服务器
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
