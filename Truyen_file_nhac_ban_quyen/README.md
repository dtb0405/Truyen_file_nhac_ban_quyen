# 🎵 Hệ Thống Mã Hóa File Nhạc Bảo Mật

## 📋 Mô tả

Hệ thống client-server để gửi file nhạc được mã hóa với các yêu cầu bảo mật cao, bao gồm:
- **Mã hóa file**: Triple DES (3DES)
- **Mã hóa metadata**: DES
- **Trao đổi khóa**: RSA 1024-bit với OAEP và SHA-256
- **Chữ ký số**: RSA 1024-bit với SHA-512
- **Kiểm tra tính toàn vẹn**: SHA-512
- **Hybrid Encryption**: Kết hợp AES và RSA cho việc mã hóa khóa
- **Quản lý khóa tự động**: Sinh key mới khi kết nối
- **Giao diện web**: Dashboard với auto-refresh

## 🏗️ Kiến trúc hệ thống

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │   Server    │    │   Uploads   │
│             │    │             │    │             │
│ • Flask     │◄──►│ • Flask     │───►│ • Files     │
│ • RSA Keys  │    │ • RSA Keys  │    │ • Metadata  │
│ • 3DES/DES  │    │ • 3DES/DES  │    │             │
│ • Hybrid    │    │ • Hybrid    │    │             │
│   Encryption│    │   Decryption│    │             │
│ • Auto Key  │    │ • Auto Key  │    │             │
│   Gen       │    │   Gen       │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

## 🔐 Tính năng bảo mật

### 1. **Mã hóa File (Triple DES)**
- Sử dụng Triple DES với mode CBC
- Session key 24 bytes được sinh ngẫu nhiên
- IV 8 bytes ngẫu nhiên cho mỗi file

### 2. **Mã hóa Metadata (DES)**
- Metadata chứa tên file và thông tin copyright
- Mã hóa bằng DES với mode ECB
- Meta key 8 bytes ngẫu nhiên

### 3. **Hybrid Encryption cho Khóa**
- Combo key (session + meta) được mã hóa bằng AES-CBC
- AES key được mã hóa bằng RSA 1024-bit + OAEP + SHA-256
- Giảm overhead so với RSA + SHA-512

### 4. **Chữ ký số và Hash**
- Hash toàn bộ file bằng SHA-512
- Chữ ký số bằng RSA 1024-bit + SHA-512
- Đảm bảo tính toàn vẹn và xác thực

### 5. **Quản lý khóa tự động**
- Tự động sinh cặp RSA key mới khi kết nối
- Lưu lịch sử sinh key
- Quản lý khóa thủ công và tự động
- Đồng bộ key giữa client-server

## 📁 Cấu trúc thư mục (ĐÃ TỐI ƯU)

```
btl (2)/
├── client/
│   ├── client_flask.py      # Client Flask application (OPTIMIZED)
│   ├── crypto_utils.py      # Client crypto utilities
│   ├── requirements.txt     # Client dependencies
│   └── key_generation.log   # Client key history
├── templates/
│   ├── client_index.html    # Client UI
│   └── server_index.html    # Server UI
├── uploads/                 # Uploaded files storage
├── metadata/               # Metadata storage
├── config.py              # Configuration file (CORE)
├── crypto_utils.py        # Shared crypto utilities (CORE)
├── server_flask.py        # Server Flask application (OPTIMIZED)
├── requirements.txt       # Server dependencies
├── key_generation.log     # Client key history
├── server_key_generation.log # Server key history
└── README.md             # Documentation
```

## 🔧 Vai trò các file Python

### **Core Files (Files chính)**

#### `config.py` - File cấu hình trung tâm
- **Vai trò**: Chứa tất cả cấu hình hệ thống ở một nơi duy nhất
- **Chức năng**:
  - Cấu hình RSA key size (1024-bit)
  - Giới hạn kích thước file upload (16MB)
  - Đường dẫn thư mục uploads
  - Tên file khóa (private/public keys)
  - Tên file log lịch sử khóa
  - Cấu hình crypto: session key size, meta key size, AES key size, IV size
  - Thuật toán hash (SHA-512, SHA-256 cho RSA OAEP)
- **Được sử dụng bởi**: Tất cả các file Python khác

#### `crypto_utils.py` - Thư viện tiện ích mã hóa
- **Vai trò**: Cung cấp các hàm tiện ích cho việc quản lý khóa RSA
- **Chức năng**:
  - `generate_key_pair()`: Tạo cặp khóa RSA và lưu vào file .pem
  - `load_public_key_pem()`: Tải public key từ file PEM
  - `load_private_key_pem()`: Tải private key từ file PEM
  - `verify_key_files_exist()`: Kiểm tra sự tồn tại của file khóa
  - `get_key_size_from_file()`: Lấy kích thước khóa từ file
- **Được sử dụng bởi**: `server_flask.py`, `client/client_flask.py`

### **Server Files (Files phía server)**

#### `server_flask.py` - Ứng dụng Flask server chính
- **Vai trò**: Server chính xử lý kết nối, upload và quản lý file
- **Chức năng chính**:
  - **Kết nối client**: Tự động sinh khóa RSA mới khi client kết nối
  - **Upload file**: Nhận file đã mã hóa, giải mã và lưu vào pending
  - **Quản lý file**: Approve/reject file, download, xóa file
  - **Dashboard**: Giao diện web với auto-refresh mỗi 3 giây
  - **Quản lý khóa**: Xem lịch sử, sinh khóa thủ công, xóa lịch sử
- **API Endpoints**:
  - `/connect`, `/disconnect`: Quản lý kết nối client
  - `/upload`: Nhận file đã mã hóa
  - `/approve_file`, `/reject_file`: Phê duyệt/từ chối file
  - `/files`, `/download/<filename>`: Quản lý file
  - `/get-dashboard-data`: Dữ liệu dashboard (auto-refresh)
  - `/server-key-history`: Lịch sử sinh khóa server

### **Client Files (Files phía client)**

#### `client/client_flask.py` - Ứng dụng Flask client
- **Vai trò**: Client giao diện web để kết nối server và upload file
- **Chức năng chính**:
  - **Kết nối server**: Tự động sinh khóa RSA mới khi kết nối
  - **Upload file**: Mã hóa file bằng Triple DES, metadata bằng DES
  - **Hybrid Encryption**: Mã hóa khóa bằng AES + RSA
  - **Chữ ký số**: Tạo chữ ký SHA-512 + RSA
  - **Quản lý khóa**: Xem lịch sử, sinh khóa thủ công, refresh server key
- **API Endpoints**:
  - `/update-server`: Kết nối đến server
  - `/upload`: Upload file đã mã hóa
  - `/check-connection`: Kiểm tra trạng thái kết nối
  - `/disconnect`: Ngắt kết nối
  - `/key-history`: Lịch sử sinh khóa client
  - `/refresh-server-key`: Làm mới khóa server

#### `client/crypto_utils.py` - Thư viện tiện ích mã hóa cho client
- **Vai trò**: Bản sao của `crypto_utils.py` chính, được sử dụng bởi client
- **Chức năng**: Giống hệt `crypto_utils.py` chính
- **Lý do tồn tại**: Client cần các hàm tiện ích nhưng chạy độc lập

### **Log Files (Files log)**

#### `key_generation.log` - Lịch sử sinh khóa client
- **Vai trò**: Ghi lại thời gian sinh khóa RSA mới của client
- **Format**: `"Key được sinh mới vào: YYYY-MM-DD HH:MM:SS (RSA 1024-bit)"`

#### `server_key_generation.log` - Lịch sử sinh khóa server
- **Vai trò**: Ghi lại thời gian sinh khóa RSA mới của server
- **Format**: `"Server key được sinh mới vào: YYYY-MM-DD HH:MM:SS (RSA 1024-bit)"`

### **Dependency Files (Files phụ thuộc)**

#### `requirements.txt` - Dependencies cho server
- **Vai trò**: Danh sách các thư viện Python cần thiết cho server
- **Các thư viện chính**: Flask, pycryptodome, requests, werkzeug

#### `client/requirements.txt` - Dependencies cho client
- **Vai trò**: Danh sách các thư viện Python cần thiết cho client
- **Các thư viện chính**: Flask, pycryptodome, requests


## 🚀 Cài đặt và chạy

### 1. **Cài đặt dependencies**

```bash
# Cài đặt cho server
pip install -r requirements.txt

# Cài đặt cho client
cd client
pip install -r requirements.txt
```

### 2. **Chạy server**

```bash
python server_flask.py
```

Server sẽ chạy tại `http://localhost:5000`

### 3. **Chạy client**

```bash
cd client
python client_flask.py
```

Client sẽ chạy tại `http://localhost:5001`

## 🎯 Hướng dẫn sử dụng

### **Bước 1: Kết nối Client-Server**
1. Mở trình duyệt và truy cập `http://localhost:5001`
2. Nhập tên client và địa chỉ server (ví dụ: `localhost:5000`)
3. Nhấn "Connect" - hệ thống sẽ tự động sinh key mới

### **Bước 2: Upload file**
1. Chọn file nhạc cần upload
2. Nhấn "Upload File"
3. Hệ thống sẽ:
   - Mã hóa file bằng Triple DES
   - Mã hóa metadata bằng DES
   - Tạo chữ ký số
   - Gửi file đã mã hóa lên server

### **Bước 3: Quản lý file trên server**
1. Truy cập `http://localhost:5000`
2. Xem danh sách file pending (auto-refresh mỗi 3 giây)
3. Approve hoặc Reject file
4. Download file đã được approve

### **Bước 4: Quản lý khóa**
- **Xem lịch sử sinh key**: Nhấn "View Key History"
- **Sinh key thủ công**: Nhấn "Generate New Keys"
- **Xóa lịch sử**: Nhấn "Clear Key History"
- **Refresh server key**: Nhấn "Refresh Server Key"

## ⚙️ Cấu hình

File `config.py` chứa tất cả cấu hình (TỐI ƯU HÓA):

```python
# Debug mode
DEBUG_MODE = True  # Set to False in production

# RSA key settings
RSA_KEY_SIZE = 1024  # bits

# File upload settings
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = 'uploads'

# Key file names
CLIENT_PRIVATE_KEY = "client_private.pem"
CLIENT_PUBLIC_KEY = "client_public.pem"
SERVER_PRIVATE_KEY = "server_private.pem"
SERVER_PUBLIC_KEY = "server_public.pem"

# Log file names
CLIENT_KEY_LOG = "key_generation.log"
SERVER_KEY_LOG = "server_key_generation.log"

# Crypto settings
SESSION_KEY_SIZE = 24  # bytes for Triple DES
META_KEY_SIZE = 8      # bytes for DES
AES_KEY_SIZE = 16      # bytes for AES
IV_SIZE = 8           # bytes for DES/Triple DES
AES_IV_SIZE = 16      # bytes for AES

# Hash algorithms
HASH_ALGORITHM = "SHA512"
RSA_OAEP_HASH = "SHA256"  # Smaller hash for RSA OAEP to reduce overhead
```

## 🔧 API Endpoints

### **Server Endpoints**
- `GET /` - Dashboard chính (auto-refresh)
- `POST /connect` - Kết nối client
- `POST /disconnect` - Ngắt kết nối client
- `POST /upload` - Upload file đã mã hóa
- `POST /approve_file` - Approve file
- `POST /reject_file` - Reject file
- `GET /files` - Lấy danh sách file
- `GET /download/<filename>` - Download file
- `POST /delete_file` - Xóa file
- `GET /get-dashboard-data` - Dữ liệu dashboard (auto-refresh)
- `GET /server-key-history` - Lịch sử sinh key server
- `POST /generate-server-keys-manually` - Sinh key thủ công
- `POST /clear-server-key-history` - Xóa lịch sử key

### **Client Endpoints**
- `GET /` - Giao diện client
- `POST /update-server` - Cập nhật server
- `POST /upload` - Upload file
- `GET /check-connection` - Kiểm tra kết nối
- `POST /disconnect` - Ngắt kết nối
- `GET /files` - Lấy danh sách file
- `POST /delete_file` - Xóa file
- `GET /key-history` - Lịch sử sinh key client
- `POST /generate-keys-manually` - Sinh key thủ công
- `POST /clear-key-history` - Xóa lịch sử key
- `POST /refresh-server-key` - Refresh server key
- `GET /debug-status` - Trạng thái debug

## 🛡️ Tính năng bảo mật

### **1. Mã hóa mạnh**
- Triple DES cho file (168-bit effective key)
- DES cho metadata
- RSA 1024-bit cho trao đổi khóa
- AES-128 cho hybrid encryption

### **2. Xác thực và toàn vẹn**
- SHA-512 hash cho file
- RSA signature với SHA-512
- Kiểm tra hash và chữ ký số

### **3. Quản lý khóa**
- Tự động sinh key mới khi kết nối
- Lưu trữ an toàn private key
- Lịch sử sinh key đầy đủ
- Đồng bộ key giữa client-server

### **4. Bảo vệ dữ liệu**
- File được mã hóa end-to-end
- Metadata được bảo vệ
- Không lưu plaintext

## 🚀 Tối ưu hóa đã thực hiện

### **1. Code Optimization**
- Loại bỏ imports thừa (`BytesIO`, `json`)
- Tạo hệ thống debug có kiểm soát
- Sử dụng constants từ config file
- Giảm duplicate code

### **2. Configuration Management**
- Tập trung cấu hình vào `config.py`
- Dễ dàng thay đổi các thông số
- Tránh hardcode values

### **3. Debug System**
- `DEBUG_MODE` flag để bật/tắt debug
- `debug_print()` helper function
- Kiểm soát debug output tốt hơn

### **4. Performance**
- Giảm memory footprint
- Tối ưu imports
- Cải thiện maintainability

### **Lợi ích sau cleanup:**
- **Clean codebase:** Loại bỏ code không sử dụng
- **Reduced confusion:** Không còn file thừa gây nhầm lẫn
- **Better performance:** Ít file hơn, load nhanh hơn
- **Easier maintenance:** Codebase gọn gàng hơn
- **No cache conflicts:** Cache files được tái tạo khi cần

## 🐛 Debug và Troubleshooting

### **Bật/tắt debug mode**
```python
# Trong config.py
DEBUG_MODE = True   # Bật debug
DEBUG_MODE = False  # Tắt debug
```

### **Kiểm tra kết nối**
- Client: `http://localhost:5001/debug-status`
- Server: Xem console output

### **Lỗi thường gặp**
1. **"Plaintext is too long"**: RSA key size không đủ (đã fix bằng hybrid encryption)
2. **"Connection timeout"**: Server không chạy
3. **"Key loading failed"**: File key bị hỏng

## 📊 Monitoring

### **Auto-refresh Dashboard**
- Server dashboard tự động refresh mỗi 3 giây
- Hiển thị real-time status của files và clients

### **Key Management**
- Theo dõi lịch sử sinh key
- Quản lý key thủ công
- Đồng bộ key giữa client-server

## 🔄 Workflow

```
1. Client kết nối → Tự động sinh key mới
2. Client upload file → Mã hóa file + metadata
3. Server nhận file → Kiểm tra hash + signature
4. Server approve/reject → Lưu file hoặc xóa
5. Client download → Giải mã và tải về
```

## 📝 Logs

### **Key Generation Logs**
- `key_generation.log` - Client key history
- `server_key_generation.log` - Server key history

### **Debug Logs**
- Console output với debug messages (có thể tắt)
- Error tracking và troubleshooting

## 🚀 Production Deployment

### **1. Tắt debug mode**
```python
DEBUG_MODE = False
```

### **2. Tăng key size (nếu cần)**
```python
RSA_KEY_SIZE = 2048  # Tăng lên 2048-bit
```

### **3. Cấu hình HTTPS**
- Sử dụng reverse proxy (nginx)
- SSL/TLS certificates
- Secure headers

### **4. Monitoring**
- Log rotation
- Error tracking
- Performance monitoring

## 📄 License

Dự án này được phát triển cho mục đích học tập và nghiên cứu về bảo mật thông tin.

## 👥 Contributors

- **Developer**: Hệ thống mã hóa file nhạc bảo mật
- **Security**: Triple DES, RSA, Hybrid Encryption
- **UI/UX**: Flask templates với auto-refresh
- **Optimization**: Code optimization và configuration management
- **Maintenance**: Code cleanup và file management

---

**⚠️ Lưu ý**: Đây là hệ thống demo cho mục đích học tập. Trong production, hãy sử dụng các thuật toán mã hóa hiện đại hơn như AES-256 và RSA-2048/4096.

## 🎯 Tính năng nổi bật

✅ **Mã hóa bảo mật cao**: Triple DES + RSA + Hybrid Encryption  
✅ **Quản lý khóa tự động**: Sinh key mới khi kết nối  
✅ **Giao diện web**: Dashboard với auto-refresh  
✅ **Lịch sử khóa**: Theo dõi và quản lý key  
✅ **Tối ưu hóa code**: Clean code, config management  
✅ **Debug system**: Kiểm soát debug output  
✅ **Error handling**: Xử lý lỗi tốt  
✅ **Code cleanup**: Loại bỏ file thừa, tối ưu cấu trúc  
✅ **Production ready**: Sẵn sàng deploy