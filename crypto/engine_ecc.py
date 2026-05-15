# crypto/engine_ecc.py — ECC Hybrid Encryption (ECDH + HKDF + AES-256-GCM)
#
# ECC cannot directly encrypt arbitrary data — instead it uses a hybrid scheme:
#   1. Generate an ephemeral EC key pair
#   2. ECDH key exchange → shared secret
#   3. HKDF to derive a symmetric AES-256-GCM key
#   4. AES-256-GCM encrypts the actual file data
#
# This mirrors how real-world ECC encryption works (e.g. ECIES, age, PGP/ECC).
#
# Key files:
#   <name>.priv.pem  — private key (keep secret, used to decrypt)
#   <name>.pub.pem   — public key  (share freely, used to encrypt)
#
# Vault payload layout:
#   [ Ephemeral pubkey length (2 bytes) | Ephemeral pubkey (DER) |
#     Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# Requires: pip install cryptography

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, generate_private_key,
    EllipticCurvePrivateKey, EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat,
    NoEncryption, load_pem_private_key, load_pem_public_key,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

CURVE     = SECP256R1()
NONCE_SIZE = 12
TAG_SIZE   = 16
KEY_SIZE   = 32


# ── Key generation ─────────────────────────────────────────────────────────────

def generate_keypair(out_stem: Path) -> tuple[Path, Path]:
    """
    Generate an EC key pair on curve P-256 and save to PEM files.
    Returns (private_key_path, public_key_path).
    """
    priv_key = generate_private_key(CURVE, default_backend())
    pub_key  = priv_key.public_key()

    priv_path = out_stem.with_suffix(".priv.pem")
    pub_path  = out_stem.with_suffix(".pub.pem")

    priv_path.write_bytes(priv_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ))
    pub_path.write_bytes(pub_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ))

    # Restrict private key file permissions on Unix
    if os.name != "nt":
        os.chmod(priv_path, 0o600)

    return priv_path, pub_path


def load_private_key(path: Path) -> EllipticCurvePrivateKey:
    return load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())


def load_public_key(path: Path) -> EllipticCurvePublicKey:
    return load_pem_public_key(path.read_bytes(), backend=default_backend())


# ── ECDH + HKDF key derivation ─────────────────────────────────────────────────

def _derive_aes_key(shared_secret: bytes, salt: bytes, info: bytes = b"ecc-cryptvault-v1") -> bytes:
    """Derive a 256-bit AES key from an ECDH shared secret using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
        backend=default_backend(),
    ).derive(shared_secret)


# ── Public API ─────────────────────────────────────────────────────────────────

def ecc_encrypt(data: bytes, pub_key: EllipticCurvePublicKey, salt: bytes) -> bytes:
    """
    Encrypt data using ECIES-style hybrid encryption:
      - Ephemeral ECDH key pair generated per encryption
      - Shared secret → HKDF → AES-256-GCM key
      - AES-256-GCM encrypts the payload

    Returns: ephkey_len (2) + ephemeral_pubkey (DER) + nonce (12) + tag (16) + ciphertext
    """
    # Ephemeral key pair — new random key each encryption for forward secrecy
    eph_priv = generate_private_key(CURVE, default_backend())
    eph_pub  = eph_priv.public_key()

    # ECDH: ephemeral private × recipient public → shared secret
    shared_secret = eph_priv.exchange(ECDH(), pub_key)
    aes_key = _derive_aes_key(shared_secret, salt)

    # Serialise ephemeral public key so recipient can reproduce the shared secret
    eph_pub_der = eph_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # AES-256-GCM encryption
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(nonce, data, associated_data=salt)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]

    # Pack ephemeral key length as 2-byte big-endian unsigned short
    eph_len = struct.pack(">H", len(eph_pub_der))
    return eph_len + eph_pub_der + nonce + tag + ciphertext


def ecc_decrypt(data: bytes, priv_key: EllipticCurvePrivateKey, salt: bytes) -> bytes:
    """
    Decrypt ECIES-style hybrid ciphertext.
    Raises ValueError on wrong key or tampered data.
    """
    if len(data) < 2:
        raise ValueError("Ciphertext too short.")

    # Unpack ephemeral public key
    eph_len = struct.unpack(">H", data[:2])[0]
    offset  = 2 + eph_len

    if len(data) < offset + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short — data may be corrupted.")

    eph_pub_der = data[2:offset]
    nonce       = data[offset:offset + NONCE_SIZE]
    tag         = data[offset + NONCE_SIZE:offset + NONCE_SIZE + TAG_SIZE]
    ciphertext  = data[offset + NONCE_SIZE + TAG_SIZE:]

    eph_pub = _load_der_pub(eph_pub_der)

    shared_secret = priv_key.exchange(ECDH(), eph_pub)
    aes_key = _derive_aes_key(shared_secret, salt)

    # AES-256-GCM decryption + verification
    aesgcm = AESGCM(aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=salt)
    except InvalidTag:
        raise ValueError("Authentication failed — wrong private key or corrupted file.")


def _load_der_pub(der: bytes) -> EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    return load_der_public_key(der, backend=default_backend())