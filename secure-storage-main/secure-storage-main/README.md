🔐 Secure Storage
一個基於 Flask + AES 加密的安全文件儲存系統，支援高效文件上傳、分塊加密、共享、下載與刪除操作。使用客戶端與伺服器分離設計，適合教學專案與安全應用的基礎實作。

✨ 功能特性
✅ 用戶註冊與登入
✅ AES 對稱加密儲存文件
✅ 分塊上傳與下載，支援局部更新
✅ 文件哈希校驗，確保完整性
✅ 檔案共享功能
✅ 權限控制：使用者只能存取自己的文件或被分享的文件
✅ 本機儲存 hashmap 映射
✅ 檔案刪除、密碼修改等實用操作
🖼️ 系統結構
client_main.py：命令列客戶端入口
client_functions.py：使用者認證與金鑰管理
clientfile_handler.py：上傳、下載、分享、刪除等核心功能
server.py：Flask 後端服務，處理各類 API 請求
secure_storage.db：SQLite 資料庫儲存使用者和檔案訊息
hashmap/：本地 hashmap 快取目錄
🚀 使用方法
🧱 0. 初始化資料庫（首次運行時必須執行）
第一次使用前，先執行 init_db.py 以初始化 SQLite 資料庫：

python init_db.py
你會看到提示：

🛠 Admin account created with default password: admin123
✅ Database initialized successfully with full chunked file support.
🖥 1. 啟動伺服器
確保目前目錄下有 server.py，然後在終端機中執行：

python server.py
如果成功運行，你將看到類似輸出：

* Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
💻 2. 啟動客戶端
另開一個終端機窗口，運行客戶端入口文件：

python client_main.py
📂 用戶端支援操作
✅ 註冊 / 登入
✅ 上傳檔案（分割加密 + 高效率更新）
✅ 下載檔案（自動哈希校驗）
✅ 刪除文件
✅ 修改密碼
✅ 共享檔案（透過使用者名稱授權他人存取）
✅ 顯示可存取的所有檔案（包括他人共用）
⚠️ 注意事項
所有檔案上傳前會使用 AES 加密，每個分塊分別處理。
上傳後本地會產生 hashmap/檔名.hashmap，加快後續同步。
被共享用戶在下載時，服務端會對每個分塊重新加密以保護隱私。
刪除操作會同時刪除遠端分塊和本機 hashmap。

