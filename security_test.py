import requests
import base64
from client_functions import login, decrypt_data

SERVER_URL = "http://127.0.0.1:5000"

def test_unauthorized_file_access():   
    # First, login normally
    username, aes_key = login()
    if not username or not aes_key:
        print("Login failed, cannot continue testing")
        return
    
    # Enter the target username and file name to attempt access
    target_username = input("Enter the target username: ")
    target_filename = input("Enter the filename you want to access: ")
    
    # Modify the request parameters to attempt accessing another user's file
    response = requests.get(f"{SERVER_URL}/download_chunks", params={
        "username": target_username,  # using target username
        "filename": target_filename
    })
    
    if response.status_code == 200:
        print(f"There exists a file from another user: {target_filename}")
        # Attempt to decrypt
        chunks = response.json().get("chunks", [])
        if chunks:
            print(f"Received {len(chunks)} file chunks")
            # Attempt to decrypt with the current user's key
            try:
                chunk = chunks[0]
                encrypted_data = base64.b64decode(chunk["encrypted_data"])
                iv = base64.b64decode(chunk["iv"])
                
                decrypted = decrypt_data(encrypted_data, aes_key, iv)
                print(f"Decryption result: {decrypted[:100]}")
            except Exception:
                print("Access failed")
        return True
    else:
        print(f"Access failed: {response.json().get('error')}")
        return False

if __name__ == "__main__":
    print("=== Test Unauthorized File Access ===")
    test_unauthorized_file_access()
