# crypto/engine_chameleon.py — Chameleon Steganographic Encryption Engine
#
# Concept:
#   The encrypted file is hidden inside a JPEG image by modifying pixel values.
#   The ORIGINAL, unmodified JPEG acts as the decryption key — without it, the
#   hidden data cannot be recovered. Even with the stego image in hand, an
#   attacker gains nothing without the exact original cover image.
#
# How it works:
#
#   ENCRYPT:
#     1. AES-256-GCM encrypts the raw file data using a key derived from the
#        cover image's pixel fingerprint (SHA-256 of normalised pixel array).
#        This binds decryption to the specific image.
#     2. The ciphertext is packed into a binary payload with a header that
#        stores the original filename, file size, and other metadata.
#     3. The payload bytes are embedded into the cover image's pixels using
#        2-bit LSB steganography (least-significant 2 bits of each R, G, B
#        channel). Each pixel holds 6 bits; 4 pixels hold 3 bytes.
#     4. The result is saved as a PNG (not JPEG — JPEG's lossy compression
#        would destroy the LSB data). The output looks almost identical to
#        the original cover image to the naked eye.
#
#   DECRYPT:
#     1. Load the stego PNG and the original cover JPEG.
#     2. Derive the same AES key from the cover image's pixel fingerprint.
#     3. Extract the LSB bits from the stego PNG's pixels to recover the payload.
#     4. AES-256-GCM decrypts and authenticates — if the wrong cover image is
#        supplied, the key is wrong and decryption fails with an auth error.
#
# Payload layout (embedded in pixel LSBs):
#   [ Magic (4B) | Version (1B) | Ext len (1B) | Ext (≤16B) |
#     Payload len (8B, big-endian uint64) |
#     Nonce (12B) | Tag (16B) | Ciphertext ]
#
# Capacity:
#   A W×H cover image can hold floor(W × H × 3 channels × 2 bits / 8) bytes.
#   A 1920×1080 image → ~1.55 MB capacity.
#   Capacity is checked before embedding; oversized files are rejected.
#
# Visual impact:
#   2-bit LSB modification shifts each channel value by at most ±3.
#   This is imperceptible to the human eye and survives casual inspection.
#   It does NOT survive JPEG re-compression — always save/send as PNG.
#
# Security notes:
#   • The cover image pixel hash is used as HKDF input material, not directly
#     as the key, so the key is always 256-bit regardless of image size.
#   • AES-256-GCM provides authenticated encryption — tampering with the stego
#     image is detected at decryption time.
#   • Using a different (wrong) cover image produces a different AES key,
#     causing an InvalidTag error. No partial data is ever returned.
#   • Statistical steganalysis tools (chi-square, RS) may detect LSB embedding
#     in sufficiently uniform regions. This engine prioritises practicality
#     over defeating forensic analysis.
#
# Requires: pip install cryptography pillow numpy

import os
import io
import struct
import hashlib
import numpy as np
from pathlib import Path
from PIL import Image

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ── Constants ──────────────────────────────────────────────────────────────────

MAGIC        = b"CHAM"          # 4-byte magic identifier
VERSION      = 1                # format version
NONCE_SIZE   = 12               # AES-GCM nonce
TAG_SIZE     = 16               # AES-GCM auth tag
KEY_SIZE     = 32               # AES-256
HKDF_INFO    = b"chameleon-file2enc-v1"
BITS_PER_CH  = 2                # LSBs used per colour channel (1–4; 2 is sweet spot)
CHANNELS     = 3                # R, G, B (alpha ignored for compatibility)
BITS_PER_PX  = BITS_PER_CH * CHANNELS   # 6 bits per pixel
MASK         = (1 << BITS_PER_CH) - 1   # 0b11 for 2-bit mode

# Fixed header size = magic(4) + version(1) + ext_len(1) + ext(16) + payload_len(8)
HEADER_FIXED = 4 + 1 + 1 + 16 + 8      # = 30 bytes
MAX_EXT_LEN  = 16


# ── Key derivation from cover image ───────────────────────────────────────────

def _cover_fingerprint(cover_img: Image.Image) -> bytes:
    """
    Produce a stable 32-byte fingerprint of the cover image.
    SHA-256 is computed over the full-resolution pixel array so that
    even a single-pixel change produces a completely different fingerprint
    (and therefore a different AES key).  Resizing to a smaller canvas
    before hashing was discarding small pixel differences via LANCZOS
    interpolation, breaking the "wrong cover → wrong key" guarantee.
    """
    img = cover_img.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    return hashlib.sha256(arr.tobytes()).digest()


def _derive_key(cover_img: Image.Image, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the cover image fingerprint via HKDF."""
    fingerprint = _cover_fingerprint(cover_img)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
        backend=default_backend(),
    ).derive(fingerprint)


# ── Capacity helpers ───────────────────────────────────────────────────────────

def max_payload_bytes(img: Image.Image) -> int:
    """Maximum bytes that can be embedded in this image."""
    w, h = img.size
    total_bits = w * h * BITS_PER_PX
    return total_bits // 8


def check_capacity(img: Image.Image, payload: bytes) -> None:
    """Raise ValueError if the payload is too large for the cover image."""
    cap = max_payload_bytes(img)
    if len(payload) > cap:
        raise ValueError(
            f"Cover image is too small for this file.\n"
            f"  Image capacity : {cap:,} bytes ({cap / 1024:.1f} KB)\n"
            f"  Payload needed : {len(payload):,} bytes ({len(payload) / 1024:.1f} KB)\n"
            f"  Use a larger cover image (e.g. 1920×1080 holds ~1.5 MB)."
        )


# ── Steganography: LSB embed / extract ────────────────────────────────────────

def _embed_bits(pixels: np.ndarray, payload: bytes) -> np.ndarray:
    """
    Embed payload bytes into the 2 LSBs of each R/G/B channel.
    pixels : (H, W, 3) uint8 array.
    payload: raw bytes to embed (must fit — caller checks capacity).

    Each byte is split into four 2-bit groups (MSB-first).
    Groups are packed into a uint8 array and applied via vectorised numpy ops,
    avoiding the Python-integer sign issue with bitwise NOT on uint8.
    """
    CLEAR_MASK = np.uint8(0xFF & ~MASK)   # 0xFC — stays positive as uint8

    # ── Expand payload bytes → 2-bit groups ───────────────────────────────────
    # payload_arr : shape (N,)  uint8
    payload_arr = np.frombuffer(payload, dtype=np.uint8)
    n_bytes     = len(payload_arr)

    # For BITS_PER_CH=2: each byte → 4 groups (shifts: 6, 4, 2, 0)
    shifts      = np.arange(8 - BITS_PER_CH, -1, -BITS_PER_CH, dtype=np.uint8)
    # groups_2d : (n_bytes, groups_per_byte)  — each cell is a 2-bit value
    groups_2d   = (payload_arr[:, None] >> shifts) & np.uint8(MASK)
    groups      = groups_2d.reshape(-1).astype(np.uint8)   # flat, all positive

    n_ch = pixels.size
    if len(groups) > n_ch:
        raise ValueError("Payload too large — capacity exceeded during embedding.")

    # ── Apply to flattened pixel array ────────────────────────────────────────
    out  = pixels.copy()
    flat = out.reshape(-1)
    flat[:len(groups)] = (flat[:len(groups)] & CLEAR_MASK) | groups

    return out.reshape(pixels.shape)


def _extract_bits(pixels: np.ndarray, n_bytes: int) -> bytes:
    """
    Extract `n_bytes` from the 2 LSBs of each R/G/B channel.
    Vectorised: reads all needed channel values at once, then reassembles bytes.
    """
    groups_per_byte = 8 // BITS_PER_CH       # 4 for 2-bit mode
    n_groups        = n_bytes * groups_per_byte

    flat   = pixels.reshape(-1)[:n_groups].astype(np.uint8)
    groups = (flat & np.uint8(MASK))         # shape (n_groups,)

    # Reshape into (n_bytes, groups_per_byte) and reassemble each byte
    # shifts: [6, 4, 2, 0] for 2-bit mode
    shifts  = np.arange(8 - BITS_PER_CH, -1, -BITS_PER_CH, dtype=np.uint8)
    g2d     = groups.reshape(n_bytes, groups_per_byte)   # (n_bytes, 4)
    result  = np.bitwise_or.reduce(g2d << shifts, axis=1).astype(np.uint8)

    return result.tobytes()


# ── Payload packing / unpacking ────────────────────────────────────────────────

def _pack_payload(ext: str, encrypted_blob: bytes) -> bytes:
    """
    Pack the metadata header + encrypted blob into a single byte string
    ready for LSB embedding.

    Layout:
      MAGIC (4) | VERSION (1) | ext_len (1) | ext (≤16, zero-padded to 16) |
      payload_len (8, big-endian) | encrypted_blob
    """
    ext_bytes = ext.lstrip(".").encode("utf-8")[:MAX_EXT_LEN]
    ext_len   = len(ext_bytes)
    ext_pad   = ext_bytes.ljust(MAX_EXT_LEN, b"\x00")

    header = (
        MAGIC
        + struct.pack("B", VERSION)
        + struct.pack("B", ext_len)
        + ext_pad
        + struct.pack(">Q", len(encrypted_blob))
    )
    return header + encrypted_blob


def _unpack_header(raw: bytes) -> tuple[str, int, int]:
    """
    Parse the fixed header from the start of the extracted bytes.
    Returns (extension, encrypted_blob_length, header_size).
    Raises ValueError on bad magic or unknown version.
    """
    if len(raw) < HEADER_FIXED:
        raise ValueError("Extracted data too short — cover image may be wrong or file is corrupted.")

    magic   = raw[0:4]
    version = raw[4]
    ext_len = raw[5]
    ext_raw = raw[6:6 + MAX_EXT_LEN]
    blob_len = struct.unpack(">Q", raw[6 + MAX_EXT_LEN:6 + MAX_EXT_LEN + 8])[0]

    if magic != MAGIC:
        raise ValueError(
            "Magic bytes not found — the cover image does not match, "
            "or this is not a Chameleon-encrypted file."
        )
    if version != VERSION:
        raise ValueError(f"Unknown Chameleon format version: {version}")

    ext = ext_raw[:ext_len].decode("utf-8", errors="replace")
    return ext, blob_len, HEADER_FIXED


# ── PNG metadata keys ──────────────────────────────────────────────────────────
# The salt and format marker are stored as PNG tEXt chunks so the output file
# is a fully valid, openable PNG with no binary wrapper prepended.

META_SALT = "f2e_salt"   # hex-encoded 16-byte salt
META_VER  = "f2e_ver"    # format version tag


# ── Public API ─────────────────────────────────────────────────────────────────

def chameleon_encrypt(
    data: bytes,
    src_ext: str,
    cover_img: Image.Image,
    salt: bytes,
) -> tuple["Image.Image", "PngImagePlugin.PngInfo"]:
    """
    Encrypt `data` and embed it into a copy of `cover_img` using LSB steganography.
    The salt is stored in the PNG tEXt metadata so the output is a valid,
    openable PNG file — no binary wrapper needed.

    Returns:
        (stego_img, png_info) — pass both to img.save(path, pnginfo=png_info)

    Raises:
        ValueError if the cover image is too small for the data.
    """
    from PIL import PngImagePlugin

    # 1. Derive AES key from cover image
    key   = _derive_key(cover_img, salt)
    nonce = os.urandom(NONCE_SIZE)

    # 2. AES-256-GCM encrypt
    aesgcm      = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, data, associated_data=salt)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    blob        = nonce + tag + ciphertext

    # 3. Pack LSB payload (file header + encrypted blob)
    payload = _pack_payload(src_ext, blob)

    # 4. Capacity check
    cover_rgb = cover_img.convert("RGB")
    check_capacity(cover_rgb, payload)

    # 5. Embed into pixel LSBs
    pixels    = np.array(cover_rgb, dtype=np.uint8)
    stego_px  = _embed_bits(pixels, payload)
    stego_img = Image.fromarray(stego_px, "RGB")

    # 6. Store salt in PNG tEXt metadata (hex string, human-readable but opaque)
    png_info = PngImagePlugin.PngInfo()
    png_info.add_text(META_SALT, salt.hex())
    png_info.add_text(META_VER,  str(VERSION))

    return stego_img, png_info


def chameleon_decrypt(
    stego_img: Image.Image,
    cover_img: Image.Image,
) -> tuple[bytes, str]:
    """
    Extract and decrypt hidden data from a Chameleon PNG.
    The salt is read from the PNG's own tEXt metadata — no external salt needed.

    Args:
        stego_img : the PNG produced by chameleon_encrypt (opened with PIL)
        cover_img : the ORIGINAL, unmodified cover image (acts as decryption key)

    Returns:
        (decrypted_bytes, original_extension)  e.g. (b"...", "pdf")

    Raises:
        ValueError on wrong cover image, missing metadata, or tampered data.
    """
    # 1. Read salt from PNG metadata
    meta = getattr(stego_img, "text", {})
    if META_SALT not in meta:
        raise ValueError(
            "No Chameleon metadata found in this image.\n"
            "This may not be a Chameleon-encrypted file, or the metadata was stripped."
        )
    salt = bytes.fromhex(meta[META_SALT])

    stego_px = np.array(stego_img.convert("RGB"), dtype=np.uint8)

    # 2. Extract fixed header to get blob length
    header_raw = _extract_bits(stego_px, HEADER_FIXED)
    ext, blob_len, header_size = _unpack_header(header_raw)

    # 3. Extract full payload
    total_bytes = header_size + blob_len
    full_raw    = _extract_bits(stego_px, total_bytes)
    blob        = full_raw[header_size:]

    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Embedded payload too short — file may be corrupted.")

    nonce      = blob[:NONCE_SIZE]
    tag        = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]

    # 4. Derive key from cover image — wrong cover → wrong key → InvalidTag
    key    = _derive_key(cover_img, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=salt)
    except InvalidTag:
        raise ValueError(
            "Decryption failed — the cover image does not match the one used during "
            "encryption, or the stego image has been modified."
        )

    return plaintext, ext


# ── Utility ────────────────────────────────────────────────────────────────────

def cover_image_capacity(cover_path: Path) -> str:
    """Return a human-readable capacity string for a cover image."""
    img = Image.open(cover_path).convert("RGB")
    w, h = img.size
    cap  = max_payload_bytes(img)
    # Subtract typical header overhead
    usable = max(0, cap - HEADER_FIXED - NONCE_SIZE - TAG_SIZE)
    return (
        f"{w}×{h} px  →  "
        f"~{usable:,} bytes usable  "
        f"({usable / 1024:.0f} KB / {usable / 1048576:.2f} MB)"
    )