# crypto/engine_aesgcm.py — AES-256-GCM (Authenticated Encryption)
#
# Layout of encrypted output:
#   [ Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# GCM handles encryption + authentication in a single pass.
# Requires: pip install cryptography

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

NONCE_SIZE = 12   # 96-bit nonce — GCM standard
TAG_SIZE   = 16   # 128-bit authentication tag
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

def aesgcm_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM.
    Returns: Nonce (12) + Tag (16) + Ciphertext
    GCM appends the tag automatically at the end of the ciphertext,
    so we split it out explicitly for a clean layout.
    """
    key   = _derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # AESGCM.encrypt() returns ciphertext + 16-byte tag concatenated
    ct_with_tag = aesgcm.encrypt(nonce, data, associated_data=salt)

    ciphertext = ct_with_tag[:-TAG_SIZE]
    tag        = ct_with_tag[-TAG_SIZE:]

    return nonce + tag + ciphertext


def aesgcm_decrypt(data: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.
    Raises ValueError on wrong password or tampered data.
    """
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    nonce      = data[:NONCE_SIZE]
    tag        = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = data[NONCE_SIZE + TAG_SIZE:]

    key    = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        # Reassemble ciphertext + tag as AESGCM expects
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=salt)
    except InvalidTag:
        raise ValueError("Authentication failed — wrong password or corrupted file.")