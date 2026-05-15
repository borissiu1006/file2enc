# crypto/engine_aescbc.py — True AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
#
# Layout of encrypted output:
#   [ IV (16 bytes) | HMAC (32 bytes) | ciphertext ]
#
# Requires: pip install cryptography

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend


IV_SIZE    = 16   # AES block size
HMAC_SIZE  = 32   # SHA-256 digest size
KEY_SIZE   = 32   # 256 bits → AES-256


# ── Key derivation ─────────────────────────────────────────────────────────────

def _derive_aescbc_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive two independent 256-bit keys from the password:
      - enc_key : used for AES-256-CBC encryption
      - mac_key : used for HMAC-SHA256 authentication
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=salt,
        iterations=480_000,
        backend=default_backend(),
    )
    key_material = kdf.derive(password.encode("utf-8"))
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]


# ── Padding helpers (PKCS7) ────────────────────────────────────────────────────

def _aescbc_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def _aescbc_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# ── Public API ─────────────────────────────────────────────────────────────────

def aescbc_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypt data with AES-256-CBC, then authenticate with HMAC-SHA256.
    Returns: IV (16) + HMAC (32) + ciphertext
    """
    enc_key, mac_key = _derive_aescbc_keys(password, salt)
    iv = os.urandom(IV_SIZE)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(_aescbc_pad(data)) + encryptor.finalize()

    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + tag + ciphertext


def aescbc_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Verify HMAC-SHA256, then decrypt AES-256-CBC.
    Raises ValueError on authentication failure.
    """
    if len(data) < IV_SIZE + HMAC_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    iv         = data[:IV_SIZE]
    tag        = data[IV_SIZE:IV_SIZE + HMAC_SIZE]
    ciphertext = data[IV_SIZE + HMAC_SIZE:]

    enc_key, mac_key = _derive_aescbc_keys(password, salt)

    expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed — wrong password or corrupted file.")

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return _aescbc_unpad(decryptor.update(ciphertext) + decryptor.finalize())