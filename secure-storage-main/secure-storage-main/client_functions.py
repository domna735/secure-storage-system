import requests
import bcrypt
import base64
import os
import re
import configparser
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
# 服务器地址
SERVER_URL = "http://127.0.0.1:5000"




# 读取配置文件
config = configparser.ConfigParser()
config.read("config.ini")

MASTER_KEY = config["DEFAULT"].get("MASTER_KEY", "").strip()
SALT = config["DEFAULT"].get("SALT", "").strip().encode()  # **SALT 需要转成字节**

if not MASTER_KEY or not SALT:
    raise ValueError("MASTER_KEY or SALT is not set in config.ini!")

# ✅ **固定 PBKDF2-HMAC 生成哈希**
def hash_password(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,  # **使用固定的 SALT**
        iterations=100000
    )
    return kdf.derive(password.encode()).hex()

# ✅ 检查用户名是否合法，防止 SQL 注入等攻击
def is_valid_username(username):
    # 仅允许字母、数字和下划线，长度限制可选
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))

def generate_aes_key():
    """ 生成 256-bit AES 密钥 """
    return os.urandom(32)

def encrypt_key(aes_key):
    """ 使用 Master Key 加密 AES 密钥 """
    master_key_bytes = MASTER_KEY.encode()
    encrypted_key = base64.b64encode(bytes(a ^ b for a, b in zip(aes_key, master_key_bytes)))
    return encrypted_key.decode()

def decrypt_key(encrypted_key):
    """ 使用 Master Key 解密 AES 密钥 """
    master_key_bytes = MASTER_KEY.encode()
    aes_key = bytes(a ^ b for a, b in zip(base64.b64decode(encrypted_key), master_key_bytes))
    return aes_key

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return encrypted, iv

def view_logs():
    response = requests.get("http://127.0.0.1:5000/logs")
    if response.status_code == 200:
        logs = response.json().get("logs", [])
        print("\n--- Logs ---")
        for log in logs:
            print(f"{log['timestamp']} | {log['username']} | {log['action']}")
    else:
        print("Failed to retrieve logs:", response.json().get("error"))



# **用户注册**
def register():
    username = input("Enter username: ").strip()
    if not is_valid_username(username):
        print("Invalid username. Only letters, numbers, and underscores are allowed.")
        return
    password = input("Enter password: ").strip()

    password_hash = hash_password(password)  # ✅ **固定哈希**

    aes_key = generate_aes_key()
    encrypted_key = encrypt_key(aes_key)

    response = requests.post(f"{SERVER_URL}/register", json={
        "username": username,
        "password_hash": password_hash,  # ✅ 发送固定哈希
        "encrypted_key": encrypted_key
    })

    if response.status_code == 200:
        print("User registered successfully.")
    else:
        print("Registration failed:", response.json().get("error"))


# **用户登录**
def login():
    username = input("Enter username: ").strip()
    if not is_valid_username(username):
        print("Invalid username. Only letters, numbers, and underscores are allowed.")
        return None, None
    password = input("Enter password: ").strip()

    # 计算本地固定哈希
    password_hash = hash_password(password)

    response = requests.post(f"{SERVER_URL}/login", json={
        "username": username,
        "password_hash": password_hash  # ✅ **直接发送固定哈希**
    })

    if response.status_code == 200:
        print(f"User {username} logged in successfully.")
        encrypted_key = response.json().get("encrypted_key")
        decrypted_key = decrypt_key(encrypted_key)
        return username, decrypted_key
    else:
        print("Login failed:", response.json().get("error"))
        return None, None


# **修改密码**
def change_password(username):
    current_password = input("Enter your current password: ").strip()
    new_password = input("Enter your new password: ").strip()
    confirm_password = input("Confirm your new password: ").strip()

    if new_password != confirm_password:
        print("Passwords do not match.")
        return

    # 计算当前密码哈希
    current_password_hash = hash_password(current_password)

    # 1️⃣ 发送当前密码哈希，让 Server 验证
    response = requests.post(f"{SERVER_URL}/verify_password", json={
        "username": username,
        "password_hash": current_password_hash
    })

    if response.status_code != 200:
        print("Password change failed: Incorrect current password.")
        return

    # 2️⃣ 计算新密码哈希
    new_password_hash = hash_password(new_password)

    # 3️⃣ 发送新哈希到 Server
    response = requests.post(f"{SERVER_URL}/change_password", json={
        "username": username,
        "new_password_hash": new_password_hash
    })

    if response.status_code == 200:
        print("Password changed successfully.")
    else:
        print("Password change failed:", response.json().get("error"))
