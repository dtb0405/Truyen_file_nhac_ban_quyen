# === config.py - Cấu hình chung cho hệ thống ===

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