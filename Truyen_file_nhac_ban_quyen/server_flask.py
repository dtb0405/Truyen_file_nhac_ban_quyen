# === server_secure.py (OPTIMIZED VERSION) ===
from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import base64
import datetime
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, DES, PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
from crypto_utils import generate_key_pair, load_public_key_pem, verify_key_files_exist, get_key_size_from_file
from config import *

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def debug_print(message):
    """Helper function for debug printing"""
    if DEBUG_MODE:
        print(message)

# Tạo thư mục nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Tạo cặp khóa RSA
SERVER_PRIVATE_KEY = "server_private.pem"
SERVER_PUBLIC_KEY = "server_public.pem"

def generate_new_server_keys():
    """Tự động sinh cặp key RSA mới cho server"""
    try:
        # Tạo key mới với độ dài từ config
        key = RSA.generate(RSA_KEY_SIZE)
        
        # Lưu private key
        with open(SERVER_PRIVATE_KEY, 'wb') as f:
            f.write(key.export_key())
        
        # Lưu public key
        with open(SERVER_PUBLIC_KEY, 'wb') as f:
            f.write(key.publickey().export_key())
        
        # Tạo file log để ghi lại thời gian sinh key
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"Server key được sinh mới vào: {timestamp} (RSA {RSA_KEY_SIZE}-bit)\n"
        
        with open(SERVER_KEY_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        debug_print(f"✅ Server đã sinh cặp key RSA {RSA_KEY_SIZE}-bit mới thành công vào {timestamp}")
        return True
    except Exception as e:
        debug_print(f"❌ Lỗi khi sinh server key mới: {str(e)}")
        return False

# Khởi tạo key ban đầu nếu chưa có
if not verify_key_files_exist(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY):
    generate_new_server_keys()

server_public_pem = load_public_key_pem(SERVER_PUBLIC_KEY)

# Kiểm tra key size
key_size = get_key_size_from_file(SERVER_PRIVATE_KEY)
if key_size:
    debug_print(f"🔑 Server key size: {key_size} bits")

# Biến toàn cục
pending_files = {}            # filename -> bytes
connected_clients = {}        # ip -> name
client_public_keys = {}       # name -> public_key (PEM)

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('server_index.html', files=files, pending_files=pending_files, connected_clients=connected_clients)

@app.route('/connect', methods=['POST'])
def client_connect():
    global server_public_pem
    data = request.get_json()
    client_ip = request.remote_addr
    client_name = data.get('clientName', 'Unknown')
    client_public_key = data.get('clientPublicKey')

    if not client_public_key:
        return jsonify({'status': 'error', 'message': 'Client public key missing'}), 400

    # Tự động sinh key mới khi có client kết nối
    if generate_new_server_keys():
        # Cập nhật server_public_pem với key mới
        server_public_pem = load_public_key_pem(SERVER_PUBLIC_KEY)

    connected_clients[client_ip] = client_name
    client_public_keys[client_name] = client_public_key

    debug_print(f"[+] Client connected: {client_name} ({client_ip}) - Server key đã được sinh mới")
    return jsonify({
        'status': 'success',
        'message': 'Connected to server - Server key đã được sinh mới',
        'serverPublicKey': server_public_pem
    })

@app.route('/disconnect', methods=['POST'])
def client_disconnect():
    client_ip = request.remote_addr
    if client_ip in connected_clients:
        client_name = connected_clients[client_ip]
        del connected_clients[client_ip]
        client_public_keys.pop(client_name, None)
        debug_print(f"[-] Client disconnected: {client_name} ({client_ip})")
    return jsonify({'status': 'success', 'message': 'Disconnected'})

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        data = request.get_json()
        iv = base64.b64decode(data['iv'])
        cipher = base64.b64decode(data['cipher'])
        meta = base64.b64decode(data['meta'])
        sig = base64.b64decode(data['sig'])
        enc_key = base64.b64decode(data['key'])
        expected_hash = data['hash']
        sender = data['sender']

        # Load keys
        priv_key = RSA.import_key(open(SERVER_PRIVATE_KEY).read())
        sender_pub = RSA.import_key(client_public_keys[sender])

        # Decrypt session + meta key (Hybrid Decryption)
        # 1. Tách các phần: encrypted_aes_key + aes_iv + encrypted_combo_key
        rsa_key_size = RSA_KEY_SIZE // 8  # RSA key size in bytes
        aes_iv_size = AES_IV_SIZE
        
        encrypted_aes_key = enc_key[:rsa_key_size]
        aes_iv = enc_key[rsa_key_size:rsa_key_size + aes_iv_size]
        encrypted_combo_key = enc_key[rsa_key_size + aes_iv_size:]
        
        # 2. Giải mã AES key bằng RSA + OAEP + SHA-256
        aes_key = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256).decrypt(encrypted_aes_key)
        
        # 3. Giải mã combo key bằng AES-CBC
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        combo_key_padded = aes_cipher.decrypt(encrypted_combo_key)
        
        # 4. Loại bỏ padding
        padding_length = combo_key_padded[-1]
        combo_key = combo_key_padded[:-padding_length]
        
        session_key, meta_key = combo_key[:SESSION_KEY_SIZE], combo_key[SESSION_KEY_SIZE:]

        # Check hash
        digest = SHA512.new(iv + cipher)
        if digest.hexdigest() != expected_hash:
            return jsonify({'status': 'error', 'message': 'Hash mismatch'}), 400

        # Verify signature
        pkcs1_15.new(sender_pub).verify(digest, sig)

        # Decrypt metadata
        meta_plain = DES.new(meta_key, DES.MODE_ECB).decrypt(meta)
        meta_plain = meta_plain[:-meta_plain[-1]].decode()
        filename, _ = meta_plain.split('|', 1)

        # Decrypt file
        file_plain = DES3.new(session_key, DES3.MODE_CBC, iv).decrypt(cipher)
        file_plain = file_plain[:-file_plain[-1]]

        # Save to pending
        filename = secure_filename(filename)
        pending_files[filename] = file_plain

        return jsonify({
            'status': 'pending',
            'message': 'File pending approval',
            'filename': filename
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lỗi xử lý: {str(e)}'}), 500

@app.route('/approve_file', methods=['POST'])
def approve_file():
    filename = request.json.get('filename')
    if filename in pending_files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(file_path, 'wb') as f:
            f.write(pending_files[filename])
        del pending_files[filename]
        return jsonify({'status': 'success', 'message': 'File approved'})
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/reject_file', methods=['POST'])
def reject_file():
    filename = request.json.get('filename')
    if filename in pending_files:
        del pending_files[filename]
        return jsonify({'status': 'rejected', 'message': 'File rejected'})
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/check_file_status/<filename>')
def check_file_status(filename):
    if filename in pending_files:
        return jsonify({'status': 'pending', 'message': 'File is pending approval'})
    elif os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        return jsonify({'status': 'approved', 'message': 'File was approved'})
    else:
        return jsonify({'status': 'rejected', 'message': 'File was rejected'})

@app.route('/files')
def get_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify({
        'files': files,
        'pending_files': list(pending_files.keys())
    })

@app.route('/get-dashboard-data')
def get_dashboard_data():
    """Cung cấp dữ liệu cho dashboard auto-refresh"""
    try:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        
        # Chuyển đổi connected_clients từ dict sang list
        clients = []
        for ip, name in connected_clients.items():
            clients.append({'ip': ip, 'name': name})
        
        return jsonify({
            'status': 'success',
            'clients': clients,
            'pending_files': list(pending_files.keys()),
            'approved_files': files
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Lỗi khi lấy dữ liệu dashboard: {str(e)}'
        }), 500

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/delete_file', methods=['POST'])
def delete_file():
    filename = request.json.get('filename')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({'status': 'success', 'message': 'File deleted'})
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/server-key-history')
def get_server_key_history():
    """Lấy lịch sử sinh key của server"""
    try:
        if os.path.exists(SERVER_KEY_LOG):
            with open(SERVER_KEY_LOG, "r", encoding="utf-8") as f:
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
                'message': 'Chưa có lịch sử sinh key server'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lỗi khi đọc lịch sử: {str(e)}'}), 500

@app.route('/generate-server-keys-manually', methods=['POST'])
def generate_server_keys_manually():
    """Sinh key mới cho server theo yêu cầu thủ công"""
    try:
        if generate_new_server_keys():
            # Cập nhật server_public_pem với key mới
            global server_public_pem
            server_public_pem = load_public_key_pem(SERVER_PUBLIC_KEY)
            
            return jsonify({
                'status': 'success',
                'message': 'Đã sinh cặp key RSA mới cho server thành công'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Không thể sinh key mới cho server'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Lỗi khi sinh server key: {str(e)}'
        }), 500

@app.route('/clear-server-key-history', methods=['POST'])
def clear_server_key_history():
    """Xóa lịch sử sinh key của server"""
    try:
        if os.path.exists(SERVER_KEY_LOG):
            os.remove(SERVER_KEY_LOG)
            return jsonify({
                'status': 'success',
                'message': 'Đã xóa lịch sử sinh key server'
            })
        else:
            return jsonify({
                'status': 'success',
                'message': 'Không có lịch sử server key để xóa'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Lỗi khi xóa lịch sử server key: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
