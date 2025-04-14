# 🔐 Secure Storage
A secure file storage system based on Flask + AES encryption, which supports efficient file upload, block encryption, sharing, downloading, and deletion operations. It uses client and server separation design.

## ✨Features
- ✅ User registration and login
- ✅ AES symmetric encryption for file storage
- ✅ Block upload and download, support for local updates
- ✅ File hash verification to ensure integrity
- ✅ File sharing function
- ✅ Permission control: users can only access their own files or shared files
- ✅ Local storage hashmap mapping
- ✅ Practical operations such as file deletion and password modification

## 🖼️ System Structure
- `client_main.py`: command line client entry
- `client_functions.py`: user authentication and key management
- `clientfile_handler.py`: core functions such as upload, download, share, delete, etc.
- `server.py`: Flask backend service, handling various API requests
- `secure_storage.db`: SQLite database to store user and file information
- `hashmap/`: local hashmap cache directory
- `security_test.py`: Test whether the files uploaded by users can be decrypted or downloaded by unauthorized users or not

## 🚀 How to use

### 🧱 0. Initialize the database (must be executed when running for the first time)
Before using the database for the first time, run `pip install -r requirements.txt` to install the required packages and run `rm secure_storage.db` to clear the database

    pip install -r requirements.txt
    rm secure_storage.db


Then run `init_db.py` to initialize the SQLite database

    python init_db.py

You will see the prompt:

    🛠 Admin account created with default username: admin &  password: admin123
    ✅ Database initialized successfully with full chunked file support.

---

### 🖥 1. Start the server
Make sure there is `server.py` in the current directory, then run in the terminal:

python server.py

If it runs successfully, you will see output similar to:

    * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

---

### 💻 2. Start the client
Open another terminal window and run the client entry file:

    python client_main.py

---

### 💻 3. Test SQL injection
Input the following SQL injection strings in the useername field
- ' or 1 = 1
- abc /*。 */

---

### 💻 4. Test whether the files uploaded by users can be decrypted or downloaded by unauthorized users
Run the client entry file:

    python security_test.py

---

### 💻 4. Test SQL injection
Input the following SQL injection strings in the useername field
- ' or 1 = 1
- abc /*。 */

---

### 📂 Client support operations
- ✅ Register / Login
- ✅ Upload files (block encryption + efficient update)
- ✅ Download files (automatic hash verification)
- ✅ Delete files
- ✅ Reset password
- ✅ Share files (authorize others to access by username)
- ✅ Display all accessible files (including those shared by others)


### 📂 Admin support operations
- ✅ Register / Login
- ✅ Review the logs of all users

---

### ⚠️ Precautions
- All files will be encrypted using AES before uploading, and each block will be processed separately.
- After uploading, `hashmap/filename.hashmap` will be generated locally to speed up subsequent synchronization.
- When the shared user downloads, the server will re-encrypt each block to protect privacy.
- The delete operation will delete both the remote block and the local hashmap.
