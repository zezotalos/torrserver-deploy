from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from pbkdf2 import PBKDF2
import base64
import os


# Your secret data (e.g., API keys, credentials)
data = ''

# Generate a random salt (16 bytes)
salt = get_random_bytes(16)

# Choose a password (keep this secret!)
password = os.environ.get('SECRET_KEY')

# Derive key using PBKDF2 (AES-256 requires 32 bytes)
key = PBKDF2(password.encode(), salt, iterations=100000).read(32)

# Encrypt
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))

# Combine salt + IV + ciphertext
encrypted = salt + cipher.iv + ct_bytes

# Save to file (base64-encoded)
with open("script.enc", "wb") as f:
    f.write(base64.b64encode(encrypted))