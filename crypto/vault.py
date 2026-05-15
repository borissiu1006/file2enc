# crypto/vault.py — Unified encrypt/decrypt dispatcher for all engines
#
# ── Vault file layout (all non-Chameleon methods) ─────────────────────────────
#
#   [ Magic      (4 bytes)  "F2EV"                          ]
#   [ Version    (1 byte)   currently 0x01                  ]
#   [ Method     (1 byte)   0x01–0x06                       ]
#   [ Salt       (16 bytes) random, used for KDF             ]
#   [ Header MAC (32 bytes) HMAC-SHA256 of bytes 0..22      ]
#   [ Payload    (N bytes)  engine output                    ]
#
# The Header MAC authenticates Magic + Version + Method + Salt so that an
# attacker cannot flip the method byte or salt without detection. The payload
# itself is already authenticated by each engine's own AEAD tag / HMAC.
#
# The HMAC key for the header is derived from the payload's first 32 bytes
# XOR'd with a fixed domain separator — it requires no extra secret.
#
# ── Versioning ────────────────────────────────────────────────────────────────
# Bump VAULT_VERSION when the format changes. decrypt_file checks it and
# raises a clear error rather than silently misreading old vaults.
#
# ── Method bytes ──────────────────────────────────────────────────────────────
#   0x01 → Seq2Enc (GRU neural keystream) — experimental
#   0x02 → AES-256-CBC + HMAC-SHA256
#   0x03 → AES-256-GCM
#   0x04 → ChaCha20-Poly1305
#   0x05 → ECC (P-256 / ECIES)
#   0x06 → Signature (biometric, AES-256-GCM)
#   0x07 → Chameleon (steganographic PNG — separate format, no vault wrapper)

import io
import os
import hmac
import hashlib
from pathlib import Path
from PIL import Image

from crypto.engine_aescbc    import aescbc_encrypt,  aescbc_decrypt
from crypto.engine_seq2enc   import seq2enc
from crypto.engine_aesgcm    import aesgcm_encrypt,  aesgcm_decrypt
from crypto.engine_chacha20  import chacha_encrypt,   chacha_decrypt
from crypto.engine_ecc       import ecc_encrypt, ecc_decrypt, load_public_key, load_private_key
from crypto.engine_sig       import sig_encrypt, sig_decrypt
from crypto.engine_chameleon import chameleon_encrypt, chameleon_decrypt

# ── Format constants ───────────────────────────────────────────────────────────

VAULT_MAGIC   = b"F2EV"
VAULT_VERSION = 0x02             # V2 = Argon2id  |  V1 = PBKDF2 (legacy)
SALT_SIZE     = 16
HEADER_MAC_SIZE = 32             # HMAC-SHA256
HEADER_DOMAIN = b"file2enc-header-mac-v1"

# Fixed header size = magic(4) + version(1) + method(1) + salt(16) = 22 bytes
HEADER_SIZE   = 4 + 1 + 1 + SALT_SIZE   # 22

METHOD_SEQ       = b'\x01'
METHOD_AESCBC    = b'\x02'
METHOD_AESGCM    = b'\x03'
METHOD_CHACHA    = b'\x04'
METHOD_ECC       = b'\x05'
METHOD_SIG       = b'\x06'
METHOD_CHAMELEON = b'\x07'

METHODS = {
    "seq":       METHOD_SEQ,
    "aescbc":    METHOD_AESCBC,
    "aesgcm":    METHOD_AESGCM,
    "chacha":    METHOD_CHACHA,
    "ecc":       METHOD_ECC,
    "sig":       METHOD_SIG,
    "chameleon": METHOD_CHAMELEON,
}

__all__ = [
    "encrypt_file", "decrypt_file", "SALT_SIZE",
    "METHOD_SEQ", "METHOD_AESCBC", "METHOD_AESGCM",
    "METHOD_CHACHA", "METHOD_ECC", "METHOD_SIG", "METHOD_CHAMELEON",
]


# ── Header MAC ─────────────────────────────────────────────────────────────────

def _header_mac(header_bytes: bytes, payload: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over the 22-byte header.
    Key = SHA-256(first 32 bytes of payload XOR domain separator, zero-padded).
    This ties the header MAC to the payload without requiring a separate secret.
    """
    payload_sample = (payload[:32] + b"\x00" * 32)[:32]
    domain_padded  = (HEADER_DOMAIN + b"\x00" * 32)[:32]
    mac_key = bytes(a ^ b for a, b in zip(payload_sample, domain_padded))
    return hmac.new(mac_key, header_bytes, hashlib.sha256).digest()


def _build_vault(method_byte: bytes, salt: bytes, payload: bytes) -> bytes:
    """Assemble the full vault binary."""
    header = (
        VAULT_MAGIC
        + bytes([VAULT_VERSION])
        + method_byte
        + salt
    )
    mac = _header_mac(header, payload)
    return header + mac + payload


def _parse_vault(raw: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Parse and validate a vault binary.
    Returns (method_byte, salt, payload, header).
    Raises ValueError on bad magic, wrong version, or failed MAC.
    """
    min_size = HEADER_SIZE + HEADER_MAC_SIZE
    if len(raw) < min_size:
        raise ValueError("File too short to be a valid vault.")

    magic   = raw[0:4]
    version = raw[4]
    method  = raw[5:6]
    salt    = raw[6:6 + SALT_SIZE]
    mac     = raw[HEADER_SIZE:HEADER_SIZE + HEADER_MAC_SIZE]
    payload = raw[HEADER_SIZE + HEADER_MAC_SIZE:]
    header  = raw[:HEADER_SIZE]

    if magic != VAULT_MAGIC:
        raise ValueError(
            "Not a valid file2enc vault (bad magic bytes).\n"
            "  If this is a Chameleon PNG, provide the .png file directly."
        )
    if version not in (0x01, 0x02):
        raise ValueError(
            f"Vault version mismatch — file uses version {version}, "
            f"but this build supports versions 1 and 2.\n"
            "  Re-encrypt the file with the current version of file2enc."
        )

    # Verify header MAC
    expected_mac = _header_mac(header, payload)
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError(
            "Header integrity check failed — the vault header has been tampered with "
            "or the file is corrupted."
        )

    return method, salt, payload, header


# ── Public API ─────────────────────────────────────────────────────────────────

def encrypt_file(
    src: Path,
    dst: Path,
    password: str,
    method: str,
    pub_key_path: Path = None,
    sig_img=None,
    cover_img_path: Path = None,
) -> None:
    if method not in METHODS:
        raise ValueError(f"Unknown method '{method}'. Choose: {list(METHODS)}")

    salt     = os.urandom(SALT_SIZE)
    raw_data = src.read_bytes()

    match method:
        case "seq":
            payload = seq2enc(raw_data, password)

        case "aescbc":
            payload = aescbc_encrypt(raw_data, password, salt)

        case "aesgcm":
            payload = aesgcm_encrypt(raw_data, password, salt)

        case "chacha":
            payload = chacha_encrypt(raw_data, password, salt)

        case "ecc":
            if pub_key_path is None:
                raise ValueError("ECC encryption requires a public key file.")
            payload = ecc_encrypt(raw_data, load_public_key(pub_key_path), salt)

        case "sig":
            if sig_img is None:
                raise ValueError("Signature engine requires a signature image.")
            payload = sig_encrypt(raw_data, sig_img, salt)

        case "chameleon":
            if cover_img_path is None:
                raise ValueError("Chameleon engine requires a cover image path.")
            cover_img = Image.open(cover_img_path).convert("RGB")
            stego_img, png_info = chameleon_encrypt(raw_data, src.suffix, cover_img, salt)
            stego_img.save(str(dst), format="PNG", pnginfo=png_info)
            return   # Chameleon skips the standard vault wrapper

        case _:
            raise ValueError(f"Method '{method}' is defined but not implemented.")

    dst.write_bytes(_build_vault(METHODS[method], salt, payload))


def decrypt_file(
    src: Path,
    dst: Path,
    password: str,
    priv_key_path: Path = None,
    sig_img=None,
    cover_img_path: Path = None,
) -> None:
    raw = src.read_bytes()

    # ── Chameleon: pure PNG output, detected by PNG magic ─────────────────────
    if raw[:4] == b"\x89PNG":
        stego_img = Image.open(str(src))
        if not (hasattr(stego_img, "text") and "f2e_salt" in stego_img.text):
            raise ValueError(
                "This PNG is not a Chameleon-encrypted file (no vault metadata)."
            )
        if cover_img_path is None:
            raise ValueError("Chameleon decryption requires the original cover image.")
        cover_img = Image.open(cover_img_path).convert("RGB")
        plaintext, ext = chameleon_decrypt(stego_img, cover_img)
        out = dst.with_suffix(f".{ext}") if not dst.suffix and ext else dst
        out.write_bytes(plaintext)
        return

    # ── Standard vault ─────────────────────────────────────────────────────────
    method, salt, payload, _ = _parse_vault(raw)
    legacy = (raw[4] == 0x01)   # V1 vault → use PBKDF2; V2 → use Argon2id

    match method:
        case x if x == METHOD_SEQ:
            decrypted = seq2enc(payload, password)

        case x if x == METHOD_AESCBC:
            decrypted = aescbc_decrypt(payload, password, salt)

        case x if x == METHOD_AESGCM:
            decrypted = aesgcm_decrypt(payload, password, salt)

        case x if x == METHOD_CHACHA:
            decrypted = chacha_decrypt(payload, password, salt)

        case x if x == METHOD_ECC:
            if priv_key_path is None:
                raise ValueError("ECC decryption requires a private key file.")
            decrypted = ecc_decrypt(payload, load_private_key(priv_key_path), salt)

        case x if x == METHOD_SIG:
            if sig_img is None:
                raise ValueError("Signature engine requires a drawn signature.")
            decrypted = sig_decrypt(payload, sig_img, salt)

        case _:
            raise ValueError("Unknown vault method byte — vault may be from a newer version.")

    dst.write_bytes(decrypted)