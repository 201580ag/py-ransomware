from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# 복호화 함수
def decrypt_file(encrypted_file_path, key):
    # 암호화된 파일 읽기
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # AES 복호화 설정
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    # 복호화
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # 패딩 제거
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()

    # 원래 확장자 복원
    original_file_path = encrypted_file_path.replace('.jmtgod', '')
    with open(original_file_path, 'wb') as f:
        f.write(original_data)

    # 암호화된 파일 삭제
    os.remove(encrypted_file_path)

# 키 복원 함수
def load_key():
    with open(os.path.join(os.path.expanduser('~'), 'Desktop', 'decryptionKEY.txt'), 'r') as f:
        key_data = f.read()
    key_salt = base64.urlsafe_b64decode(key_data)
    key = key_salt[:32]
    salt = key_salt[32:]
    return key, salt

# 복호화할 파일 선택
def decrypt_files_in_folder(folder_path):
    key, salt = load_key()
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.jmtgod'):
            full_path = os.path.join(folder_path, file_name)
            decrypt_file(full_path, key)

# 바탕화면 test 폴더 경로
folder_to_decrypt = os.path.join(os.path.expanduser('~'), 'Desktop', 'test')
decrypt_files_in_folder(folder_to_decrypt)
