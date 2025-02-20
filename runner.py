import os
from cryptography.fernet import Fernet

encrypted_str = open("script" , 'r').read()
key = os.environ.get('SECRET_KEY')

fernet = Fernet(key.encode("utf-8"))
decrypted = fernet.decrypt(encrypted_str.encode()).decode()

decrypted_file = open("main.py" , 'w')
decrypted_file.write(decrypted)
