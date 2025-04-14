import requests
import bcrypt
import base64
import os
import re
import configparser
import pyotp
import qrcode
from getpass import getpass
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from clientfile_handler import safe_parse_json

# Server Address
SERVER_URL = "http://127.0.0.1:5000"

# Read configuration files
config = configparser.ConfigParser()
config.read("config.ini")

MASTER_KEY = config["DEFAULT"].get("MASTER_KEY", "").strip()
SALT = config["DEFAULT"].get("SALT", "").strip().encode()  # **SALT needs to be converted to bytes**

if not MASTER_KEY or not SALT:
    raise ValueError("MASTER_KEY or SALT is not set in config.ini!")

# ✅ **Fixed PBKDF2-HMAC Generate Hash**
def hash_password(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,  # **Use fixed SALT**
        iterations=100000
    )
    return kdf.derive(password.encode()).hex()

# ✅ Check if username is valid, prevent SQL injection and other attacks
def is_valid_username(username):
    # Only allow letters, numbers and underscores, length limit optional
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))

def generate_aes_key():
    """ Generate 256-bit AES key """
    return os.urandom(32)

def encrypt_key(aes_key):
    """ Encrypt AES key using Master Key """
    master_key_bytes = MASTER_KEY.encode()
    encrypted_key = base64.b64encode(bytes(a ^ b for a, b in zip(aes_key, master_key_bytes)))
    return encrypted_key.decode()

def decrypt_key(encrypted_key):
    """ Decrypt AES key using Master Key """
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

def generate_mfa_secret():
    """Generate a new MFA secret for a user"""
    return pyotp.random_base32()

def generate_mfa_qr_code(username, secret):
    """Generate QR code for Google Authenticator"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(username, issuer_name="Secure Storage")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(f"{username}_mfa_qr.png")
    return f"{username}_mfa_qr.png"

def verify_mfa_code(secret, code):
    """Verify if the provided MFA code is valid"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# **User Registration**
def register():
    print("\n=== User Registration ===")
    username = input("Enter username: ").strip()
    if not is_valid_username(username):
        print("Invalid username. Only letters, numbers, and underscores are allowed.")
        return
    password = input("Enter password: ").strip()
    if not password:
        print("Password cannot be empty.")
        return
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return
    confirm_password = getpass("Confirm password: ")
    if password != confirm_password:
        print("Passwords do not match.")
        return
    
    # Generate MFA secret
    mfa_secret = generate_mfa_secret()
    qr_code_path = generate_mfa_qr_code(username, mfa_secret)
    print(f"\nPlease scan the QR code ({qr_code_path}) with Google Authenticator app.")
    print("After scanning, enter the 6-digit code from the app to verify setup.")
    
    attempts = 0
    max_attempts = 3
    while True:
        mfa_code = input("Enter 6-digit code from Google Authenticator: ").strip()
        if verify_mfa_code(mfa_secret, mfa_code):
            break
        
        attempts += 1
        if attempts >= max_attempts:
            print("Too many failed attempts. Returning to main menu.")
            return False  # Return False to indicate verification failed
            
        print(f"Invalid code. Please try again. ({attempts}/{max_attempts} attempts)")


    password_hash = hash_password(password)
    aes_key = generate_aes_key()
    encrypted_key = encrypt_key(aes_key)

    response = requests.post(f"{SERVER_URL}/register", json={
        "username": username,
        "password_hash": password_hash,
        "encrypted_key": encrypted_key,
        "mfa_secret": mfa_secret
    })

    if response.status_code == 200:
        print("User registered successfully.")
        os.remove(qr_code_path)  # Clean up QR code file
    else:
        print("Registration failed:", response.json().get("error"))
        os.remove(qr_code_path)  # Clean up QR code file even if registration fails


# **User Login**
def login():
    username = input("Enter username: ").strip()
    if not is_valid_username(username):
        print("Invalid username. Only letters, numbers, and underscores are allowed.")
        return None, None
    password = input("Enter password: ").strip()

    password_hash = hash_password(password)

    # First step: verify password
    response = requests.post(f"{SERVER_URL}/login", json={
        "username": username,
        "password_hash": password_hash
    })

    if response.status_code == 200:
        # Special handling for admin user - No MFA verification needed
        if username == "admin" and password == "admin123":
            print(f"{username} logged in successfully.")
            encrypted_key = response.json().get("encrypted_key")
            decrypted_key = decrypt_key(encrypted_key)
            return username, decrypted_key
            
        # MFA verification for normal users 
        mfa_secret = response.json().get("mfa_secret")
        if mfa_secret:
            attempts = 0
            max_attempts = 3
            while True:
                mfa_code = input("Enter 6-digit code from Google Authenticator: ").strip()
                if verify_mfa_code(mfa_secret, mfa_code):
                    break
                
                attempts += 1
                if attempts >= max_attempts:
                    print("Too many failed attempts. Returning to main menu.")
                    return None, None
                    
                print(f"Invalid code. Please try again. ({attempts}/{max_attempts} attempts)")

            # Final verification with MFA code
            response = requests.post(f"{SERVER_URL}/verify_mfa", json={
                "username": username,
                "mfa_code": mfa_code
            })

            if response.status_code == 200:
                print(f"{username} logged in successfully.")
                encrypted_key = response.json().get("encrypted_key")
                decrypted_key = decrypt_key(encrypted_key)
                return username, decrypted_key
            else:
                print("MFA verification failed:", response.json().get("error"))
                return None, None
        else:
            print("Login failed: MFA not configured for this user.")
            return None, None
    else:
        print("Login failed:", response.json().get("error"))
        return None, None

def logout(username):
    """Log out the current user and record the action"""
    if not username:
        return False
    
    # Get client information
    import platform
    import socket
    
    # Collect client information
    system_info = platform.system() + " " + platform.release()
    hostname = socket.gethostname()
    client_info = f"{system_info} ({hostname})"
    
    # Send logout information to server
    response = requests.post(f"{SERVER_URL}/log_logout", json={
        "username": username,
        "client_info": client_info
    })
    
    success, data = safe_parse_json(response)
    if not success or not data.get("success", False):
        print(f"Warning: Failed to record logout. {data if success else ''}")
        return False
    
    print(f"{username} Logged out successfully.")
    return True

# **reset password**
def reset_password(username):
    current_password = input("Enter your current password: ").strip()
    new_password = input("Enter your new password: ").strip()
    confirm_password = input("Confirm your new password: ").strip()

    if new_password != confirm_password:
        print("Passwords do not match.")
        return

    # Calculate current password hash
    current_password_hash = hash_password(current_password)

    # 1️⃣ Send current password hash for Server verification
    response = requests.post(f"{SERVER_URL}/verify_password", json={
        "username": username,
        "password_hash": current_password_hash
    })

    if response.status_code != 200:
        print("Password reset failed: Incorrect current password.")
        return

    # 2️⃣ Calculate new password hash
    new_password_hash = hash_password(new_password)

    # 3️⃣ Send new hash to Server
    response = requests.post(f"{SERVER_URL}/reset_password", json={
        "username": username,
        "new_password_hash": new_password_hash
    })

    if response.status_code == 200:
        # Log the password reset action
        log_response = requests.post(f"{SERVER_URL}/log_password_reset", json={
            "username": username
        })
        
        if log_response.status_code != 200:
            print("Warning: Password resetd successfully, but failed to log the action.")
        else:
            print("Password reset successfully.")
    else:
        print("Password reset failed:", response.json().get("error"))