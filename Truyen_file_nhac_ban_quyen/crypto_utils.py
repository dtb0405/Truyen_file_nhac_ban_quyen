# === crypto_utils.py - Utility functions for crypto operations ===
from Crypto.PublicKey import RSA
import os
from config import *

def generate_key_pair(private_path, public_path):
    """
    Tạo cặp khóa RSA và lưu vào 2 file .pem nếu chưa tồn tại.
    Sử dụng key size từ config (mặc định 1024-bit).
    """
    if os.path.exists(private_path) and os.path.exists(public_path):
        return  # Nếu đã tồn tại thì không tạo lại

    # Tạo private key với key size từ config
    key = RSA.generate(RSA_KEY_SIZE)
    
    # Ghi private key ra file
    with open(private_path, 'wb') as f:
        f.write(key.export_key())
    
    # Ghi public key ra file
    with open(public_path, 'wb') as f:
        f.write(key.publickey().export_key())

def load_public_key_pem(path):
    """
    Tải nội dung PEM của public key dưới dạng chuỗi (string).
    """
    with open(path, 'rb') as f:
        return f.read().decode('utf-8')

def load_private_key_pem(path):
    """
    Tải nội dung PEM của private key dưới dạng chuỗi (string).
    """
    with open(path, 'rb') as f:
        return f.read().decode('utf-8')

def verify_key_files_exist(private_path, public_path):
    """
    Kiểm tra xem các file key có tồn tại không.
    """
    return os.path.exists(private_path) and os.path.exists(public_path)

def get_key_size_from_file(key_path):
    """
    Lấy key size từ file key (tính bằng bit).
    """
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        key = RSA.import_key(key_data)
        return key.size_in_bits()
    except Exception as e:
        print(f"Lỗi khi đọc key size: {str(e)}")
        return None
