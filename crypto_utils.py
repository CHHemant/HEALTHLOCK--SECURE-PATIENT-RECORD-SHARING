import os
from typing import Tuple
from cryptography.fernet import Fernet

FERNET_KEY_PATH = 'fernet.key'


def _load_key_from_file(path: str = FERNET_KEY_PATH) -> bytes:
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read().strip()
    return b''


def _write_key_to_file(key: bytes, path: str = FERNET_KEY_PATH) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(key)


def load_or_create_fernet(path: str = FERNET_KEY_PATH) -> Fernet:
    key = _load_key_from_file(path)
    if not key:
        key = Fernet.generate_key()
        _write_key_to_file(key, path)
    return Fernet(key)


def encrypt_text(fernet: Fernet, plaintext: str) -> bytes:
    data = plaintext.encode('utf-8')
    return fernet.encrypt(data)


def decrypt_text(fernet: Fernet, ciphertext: bytes) -> str:
    data = fernet.decrypt(ciphertext)
    return data.decode('utf-8')
