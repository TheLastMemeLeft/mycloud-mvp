# src/utils/encryption.py
"""Utilities for file encryption and decryption using AES-256."""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Tuple

def generate_key() -> bytes:
    """Generate a random 32-byte key for AES-256."""
    return os.urandom(32)

def encrypt_file(file_data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt file data with AES-256-CBC. Returns (ciphertext, IV)."""
    iv = os.urandom(16)  # 16-byte IV for CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad data to multiple of 16 bytes
    padding_length = 16 - (len(file_data) % 16)
    padded_data = file_data + bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

def decrypt_file(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt file data with AES-256-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]