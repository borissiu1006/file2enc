# crypto/engine_aescbc.py — AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
#
# Layout of encrypted output:
#   [ IV (16 bytes) | HMAC (32 bytes) | Ciphertext ]
#
# Key derivation: Argon2id via crypto/kdf.py
# Two keys are derived: enc_key (AES-256-CBC) + mac_key (HMAC-SHA256)
#
# Requires: pip install cryptography argon2-cffi

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from src.crypto.kdf import derive_keys

IV_SIZE   = 16
HMAC_SIZE = 32


def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def _unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aescbc_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Encrypt with AES-256-CBC + HMAC-SHA256 using Argon2id key derivation."""
    enc_key, mac_key = derive_keys(password, salt)
    iv = os.urandom(IV_SIZE)

    cipher     = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    encryptor  = cipher.encryptor()
    ciphertext = encryptor.update(_pad(data)) + encryptor.finalize()

    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + tag + ciphertext


def aescbc_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Verify HMAC-SHA256, then decrypt AES-256-CBC."""
    if len(data) < IV_SIZE + HMAC_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    iv         = data[:IV_SIZE]
    tag        = data[IV_SIZE:IV_SIZE + HMAC_SIZE]
    ciphertext = data[IV_SIZE + HMAC_SIZE:]

    enc_key, mac_key = derive_keys(password, salt)

    expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed — wrong password or corrupted file.")

    cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return _unpad(decryptor.update(ciphertext) + decryptor.finalize())