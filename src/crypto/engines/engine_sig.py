# crypto/engine_sig.py — Signature-based AES-256-GCM encryption engine
#
# Vault payload layout:
#   [ Sig length (4 bytes) | Signature PNG | Nonce (12 bytes) | Tag (16 bytes) | Ciphertext ]
#
# Key derivation:
#   SHA-256(signature_pixels) → HKDF → AES-256-GCM key
#
# Requires: pip install cryptography pillow torch torchvision scikit-image numpy

# WARNING: This engine is experimental and for fun only ── Signature PNG is embedded in the vault file so it can be used to derive the key.


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

NONCE_SIZE   = 12
TAG_SIZE     = 16
KEY_SIZE     = 32
SIG_INFO     = b"sig-file2enc-v1"
THRESHOLD    = 0.70   # Similarity required


# ── Signature → key derivation ─────────────────────────────────────────────────

def _normalise_sig(img: Image.Image) -> np.ndarray:
    """Resize to fixed canvas, convert to greyscale, threshold to binary."""
    img = img.convert("L").resize((256, 128), Image.LANCZOS)
    arr = np.array(img, dtype=np.float32) / 255.0
    return arr


def _sig_to_key(img: Image.Image, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the signature image."""
    arr     = _normalise_sig(img)
    px_hash = hashlib.sha256(arr.tobytes()).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=SIG_INFO,
        backend=default_backend(),
    ).derive(px_hash)


def _img_to_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _bytes_to_img(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))


# ── Similarity scoring ─────────────────────────────────────────────────────────

def _compute_similarity(img_a: Image.Image, img_b: Image.Image) -> float:
    """
    Compute similarity between two signature images using two methods:
      1. SSIM  (structural similarity — pixel level)
      2. CNN feature cosine similarity (perceptual level, torchvision ResNet)
    Final score = 0.4 × SSIM + 0.6 × CNN cosine similarity
    """
    a = _normalise_sig(img_a)
    b = _normalise_sig(img_b)

    # ── 1. SSIM ────────────────────────────────────────────────────────────────
    try:
        from skimage.metrics import structural_similarity as ssim
        ssim_score = float(ssim(a, b, data_range=1.0))
        ssim_score = max(0.0, ssim_score)
    except ImportError:
        ssim_score = 0.0

    # ── 2. CNN perceptual similarity ───────────────────────────────────────────
    try:
        import torch
        import torchvision.transforms as T
        import torchvision.models as models
        import torch.nn.functional as F

        transform = T.Compose([
            T.Resize((224, 224)),
            T.Grayscale(num_output_channels=3),
            T.ToTensor(),
            T.Normalize(mean=[0.485, 0.456, 0.406],
                        std=[0.229, 0.224, 0.225]),
        ])

        # Use MobileNetV2 — lightweight but accurate enough
        model = models.mobilenet_v2(weights=models.MobileNet_V2_Weights.DEFAULT)
        model.eval()
        # Use features before classifier
        extractor = torch.nn.Sequential(*list(model.children())[:-1])

        img_a_pil = Image.fromarray((a * 255).astype(np.uint8))
        img_b_pil = Image.fromarray((b * 255).astype(np.uint8))

        with torch.no_grad():
            ta = extractor(transform(img_a_pil).unsqueeze(0)).flatten()
            tb = extractor(transform(img_b_pil).unsqueeze(0)).flatten()
            cnn_score = float(F.cosine_similarity(ta.unsqueeze(0), tb.unsqueeze(0)))
            cnn_score = max(0.0, cnn_score)

    except (ImportError, Exception):
        cnn_score = ssim_score   # fallback to SSIM only

    score = 0.4 * ssim_score + 0.6 * cnn_score
    return round(score, 4)


# ── Public API ─────────────────────────────────────────────────────────────────

def sig_encrypt(data: bytes, sig_img: Image.Image, salt: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM with a key derived from the signature.
    Returns: sig_len (4) + sig_png + nonce (12) + tag (16) + ciphertext
    """
    key        = _sig_to_key(sig_img, salt)
    nonce      = os.urandom(NONCE_SIZE)
    aesgcm     = AESGCM(key)
    ct_tag     = aesgcm.encrypt(nonce, data, associated_data=salt)
    ciphertext = ct_tag[:-TAG_SIZE]
    tag        = ct_tag[-TAG_SIZE:]

    sig_bytes  = _img_to_bytes(sig_img)
    sig_len    = struct.pack(">I", len(sig_bytes))   # 4-byte big-endian

    return sig_len + sig_bytes + nonce + tag + ciphertext


def sig_decrypt(payload: bytes, sig_img: Image.Image, salt: bytes) -> bytes:
    """
    Verify the drawn signature against the embedded one, then decrypt.
    Raises ValueError if similarity < THRESHOLD or decryption fails.
    """
    if len(payload) < 4:
        raise ValueError("Payload too short.")

    # Unpack embedded signature
    sig_len      = struct.unpack(">I", payload[:4])[0]
    offset       = 4 + sig_len
    sig_bytes    = payload[4:offset]
    embedded_sig = _bytes_to_img(sig_bytes)

    # Similarity check
    score = _compute_similarity(embedded_sig, sig_img)
    if score < THRESHOLD:
        raise ValueError(
            f"Signature mismatch — similarity {score:.1%} is below "
            f"the required {THRESHOLD:.0%}. Decryption denied."
        )

    # Derive key from the EMBEDDED signature (used during encryption)
    key        = _sig_to_key(embedded_sig, salt)
    nonce      = payload[offset:offset + NONCE_SIZE]
    tag        = payload[offset + NONCE_SIZE:offset + NONCE_SIZE + TAG_SIZE]
    ciphertext = payload[offset + NONCE_SIZE + TAG_SIZE:]

    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, associated_data=salt)
    except InvalidTag:
        raise ValueError("Decryption failed — signature matched but key is invalid.")


def get_similarity(payload: bytes, sig_img: Image.Image) -> float:
    """Utility: return similarity score without decrypting."""
    sig_len      = struct.unpack(">I", payload[:4])[0]
    sig_bytes    = payload[4:4 + sig_len]
    embedded_sig = _bytes_to_img(sig_bytes)
    return _compute_similarity(embedded_sig, sig_img)