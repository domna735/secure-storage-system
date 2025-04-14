import base64
import hashlib
from flask import Flask, request, jsonify
import sqlite3
import pyotp

app = Flask(__name__)

# Connect to database
def get_db_connection():
    return sqlite3.connect('secure_storage.db', check_same_thread=False)
import datetime
import pytz

# Function to log actions
def log_action(username, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    cursor.execute("INSERT INTO logs (timestamp, username, action) VALUES (?, ?, ?)", 
                  (timestamp, username, action))
    conn.commit()
    conn.close()

# Check function
def is_valid_filename(filename):
    """ Verify that the file name is safe to prevent path traversal attacks """
    if not filename:
        return False
        
    # Check common path traversal patterns
    dangerous_patterns = [
        "..",            # Parent directory
        "/",             # Unix path separator
        "\\",            # Windows path separator
        "~",             # User home directory
        "$",             # Environment variable
        "|",             # Command pipe
        ">", "<",        # Redirection
        "&",             # Command connector
        "*", "?",        # Wildcards
        ";",             # Command separator
        "\"", "'",       # Quotes
        "`",             # Command substitution
        "\0",            # Null byte
    ]
    
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False
            
    # Only allow letters, numbers, underscores, hyphens and dots (for extensions)
    import re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return False
        
    # Not allow hidden files starting with a dot(.)
    if filename.startswith("."):
        return False
        
    return True

# **Store Hash**
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

# **User Registration**
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password_hash = data.get("password_hash")
    encrypted_key = data.get("encrypted_key")
    mfa_secret = data.get("mfa_secret")

# Check for SQL injection in username
    sql_patterns = ["'", ";", "--", "/*", "*/", "DROP", "SELECT", "INSERT", "DELETE", "UPDATE"]
    for pattern in sql_patterns:
        if pattern.lower() in username.lower():
            log_security_event(f"Invalid username detected. Possible SQL injection.: {username}")
            return jsonify({"error": "Invalid username. Only letters, numbers, and underscores are allowed."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash, encrypted_key, mfa_secret) VALUES (?, ?, ?, ?)", 
                       (username, password_hash, encrypted_key, mfa_secret))
        conn.commit()
        # Log the action
        log_action(username, "User registered")
        return jsonify({"message": "User registered successfully"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

# **Login Verification (Server only stores hash, doesn't decrypt password)**
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password_hash = data.get("password_hash")

    if not username or not password_hash:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, encrypted_key, mfa_secret FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result and result[0] == password_hash:
        # Log the action
        log_action(username, "User logged in")
        return jsonify({
            "message": "Login successful", 
            "encrypted_key": result[1],
            "mfa_secret": result[2]
        }), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 400

# **Verify MFA Code**
@app.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    username = data.get("username")
    mfa_code = data.get("mfa_code")

    if not username or not mfa_code:
        return jsonify({"error": "Missing username or MFA code"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT mfa_secret, encrypted_key FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return jsonify({"error": "User not found"}), 400

    mfa_secret, encrypted_key = result
    if not mfa_secret:
        return jsonify({"error": "MFA not configured for this user"}), 400

    totp = pyotp.TOTP(mfa_secret)
    if totp.verify(mfa_code):
        return jsonify({
            "message": "MFA verification successful",
            "encrypted_key": encrypted_key
        }), 200
    else:
        return jsonify({"error": "Invalid MFA code"}), 400

# **Logout**
@app.route('/log_logout', methods=['POST'])
def log_logout():
    data = request.json
    username = data.get("username")
    client_info = data.get("client_info", "Unknown client")
    
    # Log the logout action
    log_action(username, f"Logged out from {client_info}")
    
    return jsonify({"success": True}), 200

# **Reset password**
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get("username")
    new_password_hash = data.get("new_password_hash")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Password reset successfully."}), 200

# handle the requests for logs
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

# Upload chunk
@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")
    
    # Validate filename
    if not is_valid_filename(filename):
        log_security_event(f"Invalid filename detected: {filename}")
        return jsonify({"error": "Invalid filename"}), 400
    
    # Continue processing upload
    chunk_index = data.get("chunk_index")
    encrypted_data = data.get("encrypted_data")
    iv = data.get("iv")

    if not all([username, filename, chunk_index is not None, encrypted_data, iv]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # If file doesn't exist in files table, insert a file record
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    file_row = cursor.fetchone()

    if not file_row:
        cursor.execute("INSERT INTO files (owner, filename) VALUES (?, ?)", (username, filename))
        file_id = cursor.lastrowid
    else:
        file_id = file_row[0]

    # Check if current chunk already exists (avoid duplicate uploads)
    cursor.execute("SELECT 1 FROM file_chunks WHERE file_id=? AND chunk_index=?", (file_id, chunk_index))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": f"Chunk {chunk_index} already uploaded"}), 400

    # Insert chunk
    cursor.execute(
        "INSERT INTO file_chunks (file_id, chunk_index, encrypted_data, iv) VALUES (?, ?, ?, ?)",
        (file_id, chunk_index, encrypted_data, iv)
    )

    conn.commit()
    conn.close()

    log_action(username, f"Uploaded chunk {chunk_index} of file {filename}")
    return jsonify({"message": f"Chunk {chunk_index} uploaded successfully"}), 200

# Resume breakpoint
@app.route('/check_uploaded_chunks', methods=['POST'])
def check_uploaded_chunks():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")
    chunk_hashes = data.get("chunk_hashes")  # ✨ From client

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

    # ✨ Server recalculates hashes of uploaded chunks
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

# Download
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

    # ✅ Try to download as owner
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    row = cursor.fetchone()
    if row:
        file_id = row[0]
        owner = username
    else:
        # ✅ Try to download as shared recipient
        cursor.execute("""
            SELECT f.file_id, f.owner
            FROM shared_files sf
            JOIN files f ON sf.owner = f.owner AND sf.filename = f.filename
            WHERE sf.recipient=? AND sf.filename=?
        """, (username, filename))
        row = cursor.fetchone()
        if row:
            file_id, owner = row  # Note that here owner ≠ username

    if file_id is None:
        conn.close()
        return jsonify({"error": "File not found or not accessible"}), 404

    # Get chunk information
    cursor.execute("SELECT chunk_index, encrypted_data, iv FROM file_chunks WHERE file_id=? ORDER BY chunk_index ASC", (file_id,))
    chunks_raw = cursor.fetchall()

    # Check if re-encryption is needed (i.e., shared recipient)
    if owner != username:
        # Get encrypted AES keys for owner and recipient
        cursor.execute("SELECT encrypted_key FROM users WHERE username=?", (owner,))
        owner_encrypted_key = cursor.fetchone()[0]

        cursor.execute("SELECT encrypted_key FROM users WHERE username=?", (username,))
        recipient_encrypted_key = cursor.fetchone()[0]

        from client_functions import decrypt_key, encrypt_data,decrypt_data  # ✅ Make sure you have these functions
        from base64 import b64encode, b64decode

        owner_key = decrypt_key(owner_encrypted_key)          # Use Master Key to decrypt owner's AES key
        recipient_key = decrypt_key(recipient_encrypted_key)  # Use Master Key to decrypt recipient's AES key

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
        # Self access, return as is
        chunks = [
            {"chunk_index": idx, "encrypted_data": data, "iv": iv}
            for idx, data, iv in chunks_raw
        ]

    conn.close()
    return jsonify({"chunks": chunks}), 200

# Delete chunked file
@app.route('/delete_chunks', methods=['POST'])
def delete_chunks():
    data = request.json
    username = data.get("username")
    filename = data.get("filename")

    if not username or not filename:
        return jsonify({"error": "Missing parameters"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Find file ID
    cursor.execute("SELECT file_id FROM files WHERE owner=? AND filename=?", (username, filename))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    file_id = row[0]

    # Delete file chunks
    cursor.execute("DELETE FROM file_chunks WHERE file_id=?", (file_id,))
    # Delete file record
    cursor.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    # Delete share records
    cursor.execute("DELETE FROM shared_files WHERE owner=? AND filename=?", (username, filename))

    conn.commit()
    conn.close()

    log_action(username, f"Deleted file '{filename}' and related shares.")
    return jsonify({"message": f"File '{filename}' deleted successfully."}), 200


# Share
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

    # Check if the recipient exists
    cursor.execute("SELECT 1 FROM users WHERE username=?", (recipient,))
    if not cursor.fetchone():
        return jsonify({"error": "Recipient user does not exist"}), 400

    # ✅ Correct: Check file ownership in the files table
    cursor.execute("SELECT 1 FROM files WHERE owner=? AND filename=? LIMIT 1", (username, filename))
    if not cursor.fetchone():
        return jsonify({"error": "File not found or not owned by user"}), 400

    # Insert share record
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


# List
@app.route('/list_files', methods=['GET'])
def list_files():
    username = request.args.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Files owned by the user
    cursor.execute("SELECT filename FROM files WHERE owner=?", (username,))
    own_files = {row[0] for row in cursor.fetchall()}

    # Files shared with the user
    cursor.execute("SELECT filename FROM shared_files WHERE recipient=?", (username,))
    shared_files = {row[0] for row in cursor.fetchall()}

    conn.close()

    all_files = sorted(own_files.union(shared_files))

    # ✅ Return only once to ensure JSON is not polluted
    return jsonify({"files": all_files}), 200

def log_security_event(event_description):
    """Log security-related events"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (username, action) VALUES (?, ?)", 
                  ('SYSTEM', f"[SECURITY] {event_description}"))
    conn.commit()
    conn.close()

# Verify password
@app.route('/verify_password', methods=['POST'])
def verify_password():
    data = request.json
    username = data.get("username")
    password_hash = data.get("password_hash")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] == password_hash:
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Incorrect password"}), 401

# Handle password reset logging
@app.route('/log_password_reset', methods=['POST'])
def log_password_reset():
    data = request.json
    username = data.get("username")
    
    # Log the password reset action
    log_action(username, "reset password")
    
    return jsonify({"success": True}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)