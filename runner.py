import os
import base64
from cryptography.fernet import Fernet

# Read encrypted script
with open("script", "rb") as f:
    encrypted_str = f.read()

# Get the secret key from environment
raw_key = os.environ.get('SECRET_KEY')
if raw_key is None:
    raise ValueError("SECRET_KEY environment variable is not set.")

try:
    key = base64.urlsafe_b64decode(raw_key)  # Ensure correct format
    if len(key) != 32:
        raise ValueError("Decoded key is not 32 bytes long.")
except Exception as e:
    raise ValueError(f"Invalid SECRET_KEY format: {e}")

fernet = Fernet(key)

# Decrypt content
decrypted = fernet.decrypt(encrypted_str).decode()

# Write decrypted content to main.py
with open("main.py", "w") as f:
    f.write(decrypted)

print("Decryption successful!")
