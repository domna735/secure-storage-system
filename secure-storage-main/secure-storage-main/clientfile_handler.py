import requests
import os
import base64
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# === 配置 ===
SERVER_URL = "http://127.0.0.1:5000"
HASHMAP_DIR = "hashmap"
DEBUG = False

# 安全的json响应解析
def safe_parse_json(resp):
    """安全解析 JSON，返回 (success, data or error message)"""
    try:
        data = resp.json()
        return True, data
    except requests.exceptions.JSONDecodeError:
        return False, f"[非 JSON 响应] 状态码: {resp.status_code}\n内容: {resp.text[:200]}"

# === 安全检查 ===
def is_valid_filename(filename):
    invalid = ".." in filename or filename.startswith("/") or filename.startswith("\\")
    if DEBUG:
        print(f"[DEBUG] Checking filename: '{filename}' -> {'INVALID' if invalid else 'VALID'}")
    return not invalid

# === 加解密 ===
def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return encrypted, iv

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

# === 文件列表 ===
def list_user_files(username):
    try:
        resp = requests.get(f"{SERVER_URL}/list_files", params={"username": username})
    except requests.exceptions.RequestException as e:
        print("❌ Network error when requesting file list:", e)
        return None
    
    if DEBUG:
        print("[DEBUG] HTTP status:", resp.status_code)
        print("[DEBUG] Response text:", resp.text)

    try:
        data = resp.json()
    except Exception as e:
        print("❌ Failed to parse JSON from server:", e)
        return None
    
    ok, data = safe_parse_json(resp)
    if not ok:
        print("❌ Failed to parse file list.")
        if DEBUG:
            print("[DEBUG]", data)
        return None
    
    if resp.status_code != 200:
        print("Failed to retrieve file list:", data.get("error"))
        return None

    files = data.get("files", [])
    if not files:
        print("No files available.")
        return None

    print("\nAvailable files:")
    for idx, name in enumerate(files, 1):
        print(f"{idx}. {name}")
    return files


# === 文件共享 ===
def share_file(username):
    files = list_user_files(username)
    if not files:
        return

    try:
        idx = int(input("Enter the file number to share: ")) - 1
        if idx < 0 or idx >= len(files):
            print("Invalid choice.")
            return
    except ValueError:
        print("Please enter a number.")
        return

    filename = files[idx]
    recipient = input("Enter recipient username: ").strip()

    try:
        resp = requests.post(f"{SERVER_URL}/share", json={
            "username": username,
            "filename": filename,
            "recipient": recipient
        })
    except Exception as e:
        print("❌ Failed to contact server:", e)
        return

    success, data = safe_parse_json(resp)
    if not success:
        print("❌ Sharing failed:", data)
        return

    if resp.status_code == 200:
        print(f"✅ File '{filename}' shared with '{recipient}' successfully.")
    else:
        print("❌ Sharing failed:", data.get("error", "Unknown error"))

# === 上传（高效） ===
def upload_file_efficient(username, filepath, aes_key, chunk_size=4096):
    """高效分块上传文件，仅上传改动的块"""
    if not is_valid_filename(filepath) or not os.path.exists(filepath):
        print("Invalid or missing file.")
        return

    filename = os.path.basename(filepath)
    os.makedirs(HASHMAP_DIR, exist_ok=True)
    hashmap_path = os.path.join(HASHMAP_DIR, f"{filename}.hashmap")

    # 分块读取文件
    chunks = []
    with open(filepath, "rb") as f:
        while (chunk := f.read(chunk_size)):
            chunks.append(chunk)

    # 对每块加密并计算哈希
    encrypted_chunks, ivs, hashes = [], [], []
    for chunk in chunks:
        encrypted, iv = encrypt_data(chunk, aes_key)
        encrypted_chunks.append(base64.b64encode(encrypted).decode())
        ivs.append(base64.b64encode(iv).decode())
        hashes.append(hashlib.sha256(chunk).hexdigest())

    # 请求服务器检查哪些块缺失/需更新
    try:
        resp = requests.post(f"{SERVER_URL}/check_uploaded_chunks", json={
            "username": username,
            "filename": filename,
            "chunk_hashes": hashes
        })
    except Exception as e:
        print("[ERROR] Failed to contact server:", e)
        return

    success, resp_data = safe_parse_json(resp)
    if not success:
        print("❌ Failed to check chunks:", resp_data)
        return

    if resp.status_code != 200:
        print("❌ Failed to check chunks:", resp_data.get("error", "Unknown error"))
        return

    missing = resp_data.get("missing_chunks", [])
    if not missing:
        print("✅ All file chunks already uploaded. No update needed.")
        return

    # 上传缺失或已变更的块
    for i in missing:
        part = {
            "username": username,
            "filename": filename,
            "chunk_index": i,
            "encrypted_data": encrypted_chunks[i],
            "iv": ivs[i]
        }
        try:
            res = requests.post(f"{SERVER_URL}/upload_chunk", json=part)
        except Exception as e:
            print(f"❌ Chunk {i} upload failed: Network error:", e)
            return

        success, res_data = safe_parse_json(res)
        if res.status_code != 200 or not success:
            print(f"❌ Chunk {i} upload failed:", res_data.get("error", res_data if isinstance(res_data, str) else "Unknown error"))
            return

    # 本地记录 hashmap（JSON 格式）
    with open(hashmap_path, "w") as f:
        json.dump({str(i): h for i, h in enumerate(hashes)}, f)

    print(f"✅ Efficient upload complete: {len(missing)} chunks uploaded.")

# === 下载（高效） ===
def download_file_efficient(username, key):
    files = list_user_files(username)
    if not files:
        return

    try:
        choice = int(input("\nEnter file number to download: ")) - 1
        if choice < 0 or choice >= len(files):
            print("Invalid choice.")
            return
    except ValueError:
        print("Please enter a valid number.")
        return

    filename = files[choice]


    try:
        resp = requests.get(f"{SERVER_URL}/download_chunks", params={
            "username": username, "filename": filename
        })
    except requests.exceptions.RequestException as e:
        print("❌ Network error while downloading file:", e)
        return

    success, data = safe_parse_json(resp)
    if not success:
        print("❌ Download failed:", data)
        return

    if resp.status_code != 200:
        print("Download failed:", resp.json().get("error"))
        return

    chunks = resp.json().get("chunks", [])
    hashmap_path = os.path.join(HASHMAP_DIR, f"{filename}.hashmap")
    if not os.path.exists(hashmap_path):
        print("Missing local hashmap.")
        return

    with open(hashmap_path, "r") as f:
        hashes = json.load(f)

    result = bytearray()
    for chunk in chunks:
        idx = chunk["chunk_index"]
        encrypted = base64.b64decode(chunk["encrypted_data"])
        iv = base64.b64decode(chunk["iv"])
        try:
            data = decrypt_data(encrypted, key, iv)
        except Exception as e:
            print(f"Decryption failed on chunk {idx}: {e}")
            return

        if hashlib.sha256(data).hexdigest() != hashes.get(str(idx)):
            print(f"Hash mismatch on chunk {idx}. Aborting.")
            return

        result.extend(data)

    save_path = input(f"Save as (blank = current dir): ").strip()
    if not save_path:
        save_path = os.path.join(os.getcwd(), filename)

    with open(save_path, "wb") as f:
        f.write(result)
    print(f"✅ File saved at {save_path}")

# === 删除（高效） ===
def delete_file_efficient(username):
    files = list_user_files(username)
    if not files:
        return

    try:
        idx = int(input("Enter file number to delete: ")) - 1
        if idx < 0 or idx >= len(files):
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a number.")
        return

    filename = files[idx]
    try:
        resp = requests.post(f"{SERVER_URL}/delete_chunks", json={
            "username": username,
            "filename": filename
        })
    except Exception as e:
        print("❌ Delete request failed:", e)
        return

    ok, data = safe_parse_json(resp)
    if not ok:
        print("❌ Delete failed. Server returned non-JSON response.")
        if DEBUG:
            print("[DEBUG]", data)
        return
    
    if resp.status_code == 200:
        print(f"✅ Deleted '{filename}' from server.")
        path = os.path.join(HASHMAP_DIR, f"{filename}.hashmap")
        if os.path.exists(path):
            os.remove(path)
            print(f"🧹 Deleted local hashmap '{filename}.hashmap'")
    else:
        print("❌ Delete failed:", data.get("error"))

