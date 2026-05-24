# crypto/engine_chacha20.py — ChaCha20-Poly1305 (Authenticated Encryption)
#
# Layout of encrypted output:
#   [ Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# Key derivation: Argon2id via crypto/kdf.py
#
# Requires: pip install cryptography argon2-cffi

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from src.crypto.kdf import derive_key

NONCE_SIZE = 12
TAG_SIZE   = 16


def chacha_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Encrypt with ChaCha20-Poly1305 using Argon2id key derivation."""
    key    = derive_key(password, salt)
    nonce  = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(key)

    ct_with_tag = chacha.encrypt(nonce, data, associated_data=salt)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    return nonce + tag + ciphertext


def chacha_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """Decrypt and verify ChaCha20-Poly1305 ciphertext."""
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]

    try:
        return ChaCha20Poly1305(derive_key(password, salt)).decrypt(
            nonce, ciphertext + tag, associated_data=salt
        )
    except InvalidTag:
        raise ValueError("Authentication failed — wrong password or corrupted file.")