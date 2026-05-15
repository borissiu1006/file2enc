# crypto/engine_chacha20.py — ChaCha20-Poly1305 (Authenticated Encryption)
#
# Layout of encrypted output:
#   [ Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# ChaCha20 stream cipher + Poly1305 MAC, designed by Daniel J. Bernstein.
# Preferred over AES on devices lacking hardware AES acceleration.
# Requires: pip install cryptography

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

NONCE_SIZE = 12   # 96-bit nonce — required by ChaCha20-Poly1305
TAG_SIZE   = 16   # 128-bit Poly1305 authentication tag
KEY_SIZE   = 32   # 256-bit key


# ── Key derivation ─────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=480_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


# ── Public API ─────────────────────────────────────────────────────────────────

def chacha_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypt data with ChaCha20-Poly1305.
    Returns: Nonce (12) + Tag (16) + Ciphertext
    """
    key   = _derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(key)

    # encrypt() returns ciphertext + 16-byte Poly1305 tag
    ct_with_tag = chacha.encrypt(nonce, data, associated_data=salt)

    ciphertext = ct_with_tag[:-TAG_SIZE]
    tag        = ct_with_tag[-TAG_SIZE:]

    return nonce + tag + ciphertext


def chacha_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypt and verify ChaCha20-Poly1305 ciphertext.
    Raises ValueError on wrong password or tampered data.
    """
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]

    key    = _derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)

    try:
        return chacha.decrypt(nonce, ciphertext + tag, associated_data=salt)
    except InvalidTag:
        raise ValueError("Authentication failed — wrong password or corrupted file.")