# === client_secure.py (OPTIMIZED VERSION) ===
from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlparse
from Crypto.Cipher import DES3, DES, PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
import base64
import os
import datetime
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import *
from crypto_utils import verify_key_files_exist, get_key_size_from_file

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), '../templates'))

# Configuration
DEBUG_MODE = True  # Set to False in production

def debug_print(message):
    """Helper function for debug printing"""
    if DEBUG_MODE:
        print(message)

# GLOBAL STATE
SERVER_URL = None
connected = False
server_ip = None
client_name = None
server_public_key = None

# RSA keys
CLIENT_PRIVATE_KEY = "client_private.pem"
CLIENT_PUBLIC_KEY = "client_public.pem"

def generate_new_keys():
    """Tự động sinh cặp key RSA mới"""
    try:
        # Tạo key mới với độ dài từ config
        key = RSA.generate(RSA_KEY_SIZE)
        
        # Lưu private key
        with open(CLIENT_PRIVATE_KEY, 'wb') as f:
            f.write(key.export_key())
        
        # Lưu public key
        with open(CLIENT_PUBLIC_KEY, 'wb') as f:
            f.write(key.publickey().export_key())
        
        # Tạo file log để ghi lại thời gian sinh key
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"Key được sinh mới vào: {timestamp} (RSA {RSA_KEY_SIZE}-bit)\n"
        
        with open(CLIENT_KEY_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        debug_print(f"✅ Đã sinh cặp key RSA {RSA_KEY_SIZE}-bit mới thành công vào {timestamp}")
        return True
    except Exception as e:
        debug_print(f"❌ Lỗi khi sinh key mới: {str(e)}")
        return False

# Khởi tạo key ban đầu nếu chưa có
if not verify_key_files_exist(CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY):
    debug_print("🔑 Tạo key ban đầu...")
    generate_new_keys()

# Đảm bảo key tồn tại trước khi đọc
if not verify_key_files_exist(CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY):
    debug_print("❌ Không thể tạo key ban đầu!")
    raise Exception("Không thể tạo key RSA ban đầu")

client_public_pem = open(CLIENT_PUBLIC_KEY).read()
debug_print("✅ Client key loaded successfully")

# Kiểm tra key size
key_size = get_key_size_from_file(CLIENT_PRIVATE_KEY)
if key_size:
    debug_print(f"🔑 Key size: {key_size} bits")

@app.route('/update-server', methods=['POST'])
def update_server():
    global SERVER_URL, connected, server_ip, client_name, server_public_key, client_public_pem
    data = request.get_json()
    new_server_url = data.get('server_url')
    client_name = data.get('clientName')

    if not client_name:
        return jsonify({'status': 'error','message': 'Client name is required'}), 400
    if not new_server_url:
        return jsonify({'status': 'error','message': 'No server URL provided'}), 400
    if not new_server_url.startswith(('http://', 'https://')):
        new_server_url = 'http://' + new_server_url
    try:
        parsed = urlparse(new_server_url)
        if not parsed.netloc:
            return jsonify({'status': 'error','message': 'Invalid URL format. Please use format: IP:port'}), 400
    except Exception:
        return jsonify({'status': 'error','message': 'Invalid URL format'}), 400
    try:
        response = requests.get(new_server_url, timeout=5)
        if response.status_code == 200:
            # Tự động sinh key mới trước khi kết nối
            if generate_new_keys():
                # Cập nhật client_public_pem với key mới
                client_public_pem = open(CLIENT_PUBLIC_KEY).read()
            
            connect_response = requests.post(
                f"{new_server_url}/connect",
                json={
                    'clientName': client_name,
                    'clientPublicKey': client_public_pem
                },
                timeout=5
            )
            if connect_response.status_code == 200:
                data = connect_response.json()
                server_public_key = data.get('serverPublicKey')
                SERVER_URL = new_server_url
                connected = True
                server_ip = SERVER_URL.split('//')[1]
                return jsonify({
                    'status': 'connected',
                    'server_ip': server_ip,
                    'message': 'Kết nối thành công và đã sinh key mới'
                })
            else:
                return jsonify({'status': 'error','message': f'Failed to register with server (Status: {connect_response.status_code})'}), 500
        else:
            return jsonify({'status': 'error','message': f'Server responded with status code: {response.status_code}'}), 500
    except requests.exceptions.Timeout:
        return jsonify({'status': 'error','message': 'Connection timeout. Please check if server is running and accessible.'}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error','message': 'Could not connect to server. Please check the IP address and port.'}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'status': 'error','message': f'Connection error: {str(e)}'}), 500

@app.route('/')
def index():
    global connected, server_ip, client_name
    if not SERVER_URL:
        connected = False
        server_ip = None
    return render_template('client_index.html', connected=connected, server_ip=server_ip, client_name=client_name)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400

    try:
        debug_print(f"🔍 Debug: Bắt đầu upload file {file.filename}")
        debug_print(f"🔍 Debug: SERVER_URL = {SERVER_URL}")
        debug_print(f"🔍 Debug: server_public_key exists = {server_public_key is not None}")
        debug_print(f"🔍 Debug: CLIENT_PRIVATE_KEY exists = {os.path.exists(CLIENT_PRIVATE_KEY)}")
        debug_print(f"🔍 Debug: CLIENT_PUBLIC_KEY exists = {os.path.exists(CLIENT_PUBLIC_KEY)}")
        
        # Kiểm tra xem có cần cập nhật key không
        if not server_public_key:
            return jsonify({'status': 'error', 'message': 'Server public key not available. Please reconnect to server.'}), 400
        
        # Load keys
        try:
            receiver_pub = RSA.import_key(server_public_key.encode())
            sender_priv = RSA.import_key(open(CLIENT_PRIVATE_KEY).read())
            debug_print(f"🔍 Debug: Keys loaded successfully")
        except Exception as key_error:
            debug_print(f"❌ Key loading error: {str(key_error)}")
            return jsonify({'status': 'error', 'message': 'Key loading failed. Please reconnect to server.'}), 400

        file_bytes = file.read()
        filename = file.filename
        copyright_info = "full-access"
        debug_print(f"🔍 Debug: File size = {len(file_bytes)} bytes")

        # Prepare metadata
        metadata = f"{filename}|{copyright_info}".encode()

        # Keys and IV
        session_key = get_random_bytes(SESSION_KEY_SIZE)
        meta_key = get_random_bytes(META_KEY_SIZE)
        iv = get_random_bytes(IV_SIZE)
        debug_print(f"🔍 Debug: Session keys generated")

        # Encrypt file
        cipher3 = DES3.new(session_key, DES3.MODE_CBC, iv)
        pad_len = 8 - len(file_bytes) % 8
        encrypted_file = cipher3.encrypt(file_bytes + bytes([pad_len]) * pad_len)
        debug_print(f"🔍 Debug: File encrypted")

        # Encrypt metadata
        cipher_meta = DES.new(meta_key, DES.MODE_ECB)
        pad_meta_len = 8 - len(metadata) % 8
        encrypted_meta = cipher_meta.encrypt(metadata + bytes([pad_meta_len]) * pad_meta_len)
        debug_print(f"🔍 Debug: Metadata encrypted")

        # Hash + Sign
        digest = SHA512.new(iv + encrypted_file)
        signature = pkcs1_15.new(sender_priv).sign(digest)
        debug_print(f"🔍 Debug: Hash and signature created")

        # Encrypt session + meta key with Hybrid Encryption
        combo_key = session_key + meta_key
        debug_print(f"🔍 Debug: Combo key length = {len(combo_key)} bytes")
        debug_print(f"🔍 Debug: Session key length = {len(session_key)} bytes")
        debug_print(f"🔍 Debug: Meta key length = {len(meta_key)} bytes")
        
        # Hybrid Encryption: Mã hóa combo key bằng AES, AES key bằng RSA
        # 1. Tạo AES key và IV
        aes_key = get_random_bytes(AES_KEY_SIZE)
        aes_iv = get_random_bytes(AES_IV_SIZE)
        
        # 2. Mã hóa combo key bằng AES-CBC
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        # Padding cho combo key để chia hết cho 16
        combo_key_padded = combo_key + bytes([16 - len(combo_key) % 16]) * (16 - len(combo_key) % 16)
        encrypted_combo_key = aes_cipher.encrypt(combo_key_padded)
        
        # 3. Mã hóa AES key bằng RSA + OAEP + SHA-256 (giảm overhead)
        encrypted_aes_key = PKCS1_OAEP.new(receiver_pub, hashAlgo=SHA256).encrypt(aes_key)
        
        # 4. Kết hợp: encrypted_aes_key + aes_iv + encrypted_combo_key
        enc_key = encrypted_aes_key + aes_iv + encrypted_combo_key
        debug_print(f"🔍 Debug: Hybrid encryption completed")

        # Prepare payload
        payload = {
            'iv': base64.b64encode(iv).decode(),
            'cipher': base64.b64encode(encrypted_file).decode(),
            'meta': base64.b64encode(encrypted_meta).decode(),
            'hash': digest.hexdigest(),
            'sig': base64.b64encode(signature).decode(),
            'key': base64.b64encode(enc_key).decode(),
            'sender': client_name
        }
        debug_print(f"🔍 Debug: Payload prepared, sending to server...")
        
        response = requests.post(f'{SERVER_URL}/upload', json=payload)
        debug_print(f"🔍 Debug: Server response status = {response.status_code}")
        
        return jsonify(response.json())

    except Exception as e:
        debug_print(f"❌ Error in upload_file: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': f'Upload failed: {str(e)}'}), 500

@app.route('/check_file_status/<filename>')
def check_file_status(filename):
    try:
        response = requests.get(f'{SERVER_URL}/check_file_status/{filename}')
        return response.json() if response.status_code == 200 else jsonify({'status': 'error', 'message': 'Error checking file status'}), response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error', 'message': 'Could not connect to server'}), 500

@app.route('/check-connection')
def check_connection():
    global connected, server_ip
    if not SERVER_URL:
        connected = False
        server_ip = None
        return jsonify({'status': 'disconnected','message': 'No server URL configured'})
    try:
        response = requests.get(SERVER_URL)
        if response.status_code == 200:
            connected = True
            server_ip = SERVER_URL.split('//')[1]
            return jsonify({'status': 'connected', 'server_ip': server_ip})
        else:
            connected = False
            server_ip = None
            return jsonify({'status': 'disconnected', 'message': 'Server not responding'})
    except:
        connected = False
        server_ip = None
        return jsonify({'status': 'error', 'message': 'Could not connect to server'}), 500

@app.route('/disconnect', methods=['POST'])
def disconnect():
    global SERVER_URL, connected, server_ip, client_name, server_public_key
    if SERVER_URL:
        try: requests.post(f"{SERVER_URL}/disconnect")
        except: pass
    SERVER_URL = None
    connected = False
    server_ip = None
    client_name = None
    server_public_key = None
    return jsonify({'status': 'success', 'message': 'Disconnected'})

@app.route('/files')
def get_files():
    try:
        response = requests.get(f'{SERVER_URL}/files')
        return response.json() if response.status_code == 200 else {'files': [], 'pending_files': []}
    except:
        return {'files': [], 'pending_files': []}

@app.route('/delete_file', methods=['POST'])
def delete_file():
    data = request.get_json()
    filename = data.get('filename')
    try:
        response = requests.post(f'{SERVER_URL}/delete_file', json={'filename': filename})
        return jsonify(response.json()), response.status_code
    except:
        return jsonify({'status': 'error', 'message': 'Could not delete file'}), 500

@app.route('/key-history')
def get_key_history():
    """Lấy lịch sử sinh key"""
    try:
        if os.path.exists("key_generation.log"):
            with open("key_generation.log", "r", encoding="utf-8") as f:
                history = f.readlines()
            return jsonify({
                'status': 'success',
                'history': history,
                'total_generations': len(history)
            })
        else:
            return jsonify({
                'status': 'success',
                'history': [],
                'total_generations': 0,
                'message': 'Chưa có lịch sử sinh key'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lỗi khi đọc lịch sử: {str(e)}'}), 500

@app.route('/generate-keys-manually', methods=['POST'])
def generate_keys_manually():
    """Sinh key mới theo yêu cầu thủ công"""
    try:
        if generate_new_keys():
            # Cập nhật client_public_pem với key mới
            global client_public_pem
            client_public_pem = open(CLIENT_PUBLIC_KEY).read()
            
            return jsonify({
                'status': 'success',
                'message': 'Đã sinh cặp key RSA mới thành công'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Không thể sinh key mới'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Lỗi khi sinh key: {str(e)}'
        }), 500

@app.route('/clear-key-history', methods=['POST'])
def clear_key_history():
    """Xóa lịch sử sinh key"""
    try:
        if os.path.exists("key_generation.log"):
            os.remove("key_generation.log")
            return jsonify({
                'status': 'success',
                'message': 'Đã xóa lịch sử sinh key'
            })
        else:
            return jsonify({
                'status': 'success',
                'message': 'Không có lịch sử để xóa'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Lỗi khi xóa lịch sử: {str(e)}'
        }), 500

@app.route('/debug-status')
def debug_status():
    """Debug route để kiểm tra trạng thái"""
    try:
        return jsonify({
            'status': 'success',
            'connected': connected,
            'server_url': SERVER_URL,
            'server_ip': server_ip,
            'client_name': client_name,
            'server_public_key_exists': server_public_key is not None,
            'client_private_key_exists': os.path.exists(CLIENT_PRIVATE_KEY),
            'client_public_key_exists': os.path.exists(CLIENT_PUBLIC_KEY),
            'current_directory': os.getcwd(),
            'files_in_directory': os.listdir('.')
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Debug error: {str(e)}'
        }), 500

@app.route('/refresh-server-key', methods=['POST'])
def refresh_server_key():
    """Làm mới server public key"""
    global server_public_key
    try:
        if not SERVER_URL:
            return jsonify({'status': 'error', 'message': 'Not connected to server'}), 400
        
        # Lấy server public key mới
        response = requests.get(f'{SERVER_URL}')
        if response.status_code == 200:
            # Thử kết nối lại để lấy key mới
            connect_response = requests.post(
                f"{SERVER_URL}/connect",
                json={
                    'clientName': client_name,
                    'clientPublicKey': client_public_pem
                },
                timeout=5
            )
            if connect_response.status_code == 200:
                data = connect_response.json()
                server_public_key = data.get('serverPublicKey')
                return jsonify({
                    'status': 'success',
                    'message': 'Server key refreshed successfully'
                })
            else:
                return jsonify({'status': 'error', 'message': 'Failed to refresh server key'}), 500
        else:
            return jsonify({'status': 'error', 'message': 'Server not responding'}), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error refreshing server key: {str(e)}'
        }), 500

def cleanup():
    if SERVER_URL and connected:
        try: requests.post(f"{SERVER_URL}/disconnect")
        except: pass

if __name__ == '__main__':
    import atexit
    atexit.register(cleanup)
    app.run(host='0.0.0.0', port=5001, debug=True)
