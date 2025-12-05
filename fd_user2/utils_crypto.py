# utils_crypto.py
"""
Simple AES-GCM wrapper and base64 helpers.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple

class AESCipher:
    def __init__(self, key: bytes):
        # key should be 16/24/32 bytes for AES
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        aead = AESGCM(self.key)
        ciphertext = aead.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, ciphertext_with_nonce: bytes) -> bytes:
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]
        aead = AESGCM(self.key)
        return aead.decrypt(nonce, ciphertext, None)

# helpers for base64 encoding/decoding
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    return base64.b64decode(s)
