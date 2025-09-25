# src/utils/hashing.py
"""Utilities for computing file hashes."""
import hashlib
from typing import BinaryIO

def compute_hash(file: BinaryIO) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    file.seek(0)
    while chunk := file.read(4096):
        sha256.update(chunk)
    file.seek(0)  # Reset file pointer
    return sha256.hexdigest()