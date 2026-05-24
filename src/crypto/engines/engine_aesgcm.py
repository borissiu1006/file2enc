# crypto/engine_aesgcm.py — AES-256-GCM (Authenticated Encryption)
#
# Layout of encrypted output:
#   [ Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# Key derivation: Argon2id via crypto/kdf.py
#
# Requires: pip install cryptography argon2-cffi

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from src.crypto.kdf import derive_key

NONCE_SIZE = 12
TAG_SIZE   = 16


def aesgcm_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Encrypt with AES-256-GCM using Argon2id key derivation."""
    key    = derive_key(password, salt)
    nonce  = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    ct_with_tag = aesgcm.encrypt(nonce, data, associated_data=salt)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    return nonce + tag + ciphertext


def aesgcm_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Decrypt and verify AES-256-GCM ciphertext."""
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]

    try:
        return AESGCM(derive_key(password, salt)).decrypt(
            nonce, ciphertext + tag, associated_data=salt
        )
    except InvalidTag:
        raise ValueError("Authentication failed — wrong password or corrupted file.")