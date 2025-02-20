from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pbkdf2 import PBKDF2
import base64
import os

# Use the same password as in encryption
password = os.environ.get('SECRET_KEY')

# Read the encrypted file (base64-encoded)
with open("script.enc", "rb") as f:
    encrypted_data = base64.b64decode(f.read())

# Extract salt (first 16 bytes), IV (next 16 bytes), and ciphertext (remaining bytes)
salt = encrypted_data[:16]
iv = encrypted_data[16:32]
ct_bytes = encrypted_data[32:]

# Re-derive the key using PBKDF2 (AES-256 requires 32 bytes)
key = PBKDF2(password.encode(), salt, iterations=100000).read(32)

# Initialize the cipher for decryption (using CBC mode and the extracted IV)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

# Decrypt and then remove the padding
decrypted = unpad(cipher.decrypt(ct_bytes), AES.block_size)
decrypted_text = decrypted.decode('utf-8')

# Write the decrypted content to a file (or handle it as needed)
with open("main.py", "w") as f:
    f.write(decrypted_text)

print("Decryption successful!")
