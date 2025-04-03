# 🔐 Secure Storage

一个基于 Flask + AES 加密的安全文件存储系统，支持高效文件上传、分块加密、共享、下载与删除操作。使用客户端和服务器分离设计，适合教学项目与安全应用的基础实现。

## ✨ 功能特性

- ✅ 用户注册与登录
- ✅ AES 对称加密存储文件
- ✅ 分块上传与下载，支持局部更新
- ✅ 文件哈希校验，确保完整性
- ✅ 文件共享功能
- ✅ 权限控制：用户只能访问自己的文件或被共享的文件
- ✅ 本地存储 hashmap 映射
- ✅ 文件删除、密码修改等实用操作

## 🖼️ 系统结构

- `client_main.py`：命令行客户端入口
- `client_functions.py`：用户认证与密钥管理
- `clientfile_handler.py`：上传、下载、共享、删除等核心功能
- `server.py`：Flask 后端服务，处理各类 API 请求
- `secure_storage.db`：SQLite 数据库存储用户和文件信息
- `hashmap/`：本地 hashmap 缓存目录

## 🚀 使用方法

### 🧱 0. 初始化数据库（首次运行时必须执行）

第一次使用前，先运行 `init_db.py` 以初始化 SQLite 数据库：

    python init_db.py

你会看到提示：

    🛠 Admin account created with default password: admin123
    ✅ Database initialized successfully with full chunked file support.

---

### 🖥 1. 启动服务器

确保当前目录下有 `server.py`，然后在终端中运行：

    python server.py

如果成功运行，你将看到类似输出：

    * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

---

### 💻 2. 启动客户端

另开一个终端窗口，运行客户端入口文件：

    python client_main.py

---

### 📂 客户端支持操作

- ✅ 注册 / 登录
- ✅ 上传文件（分块加密 + 高效更新）
- ✅ 下载文件（自动哈希校验）
- ✅ 删除文件
- ✅ 修改密码
- ✅ 共享文件（通过用户名授权他人访问）
- ✅ 显示可访问的所有文件（包括他人共享）

---

### ⚠️ 注意事项

- 所有文件上传前会使用 AES 加密，每个分块分别处理。
- 上传后本地会生成 `hashmap/文件名.hashmap`，加快后续同步。
- 被共享用户在下载时，服务端会对每个分块重新加密以保护隐私。
- 删除操作会同时删除远端分块和本地 hashmap。
