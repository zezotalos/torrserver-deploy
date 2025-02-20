import os
from cryptography.fernet import Fernet
import base64

encrypted_str = open("script" , 'r').read()
raw_key = os.environ.get('SECRET_KEY')
if raw_key is None:
    raise ValueError("SECRET_KEY environment variable is not set.")

key = base64.urlsafe_b64decode(raw_key)  

decrypted = Fernet(key).decrypt(encrypted_str.encode()).decode()

decrypted_file = open("main.py" , 'w')
decrypted_file.write(decrypted)
