# crypto/engine_seq2enc.py
#
# Seq2Enc: uses a GRU neural network as a keystream generator.
# The model weights are derived entirely from the password via Argon2id,
# making the network fully deterministic across all runs and platforms.
# XOR is symmetric, so the same function encrypts AND decrypts.
#
# Requires: pip install torch

# WARNING: This engine is experimental and for fun only ── GRU has no cryptographic security proofs and may have weaknesses.

import hashlib
import struct
import torch
import torch.nn as nn
from src.crypto.kdf import derive_key as _argon2_derive


# ── Model ──────────────────────────────────────────────────────────────────────

INPUT_SIZE  = 1
HIDDEN_SIZE = 64
FIXED_SALT = b"seq2enc-file2enc-v1"  # public, never changes


class KeystreamGRU(nn.Module):
    def __init__(self):
        super().__init__()
        self.gru = nn.GRU(INPUT_SIZE, HIDDEN_SIZE, batch_first=True)
        self.fc  = nn.Linear(HIDDEN_SIZE, INPUT_SIZE)

    def forward(self, x: torch.Tensor, hidden: torch.Tensor):
        out, hidden = self.gru(x, hidden)
        out = torch.sigmoid(self.fc(out))  # (1, seq_len, 1) in [0, 1]
        return out, hidden


# ── Weight derivation ──────────────────────────────────────────────────────────

def _count_params(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


def _load_weights_from_password(model: nn.Module, password: str) -> None:
    """
    Derive all model weights deterministically from the password using Argon2id.
    Each parameter tensor is filled from a slice of the derived byte stream.
    """
    n_params = _count_params(model)
    n_bytes  = n_params * 4  # float32 = 4 bytes each

    # Seed from Argon2id (32 bytes), then chain SHA-256 until we have enough
    seed_bytes = _argon2_derive(password, FIXED_SALT)  # 32 bytes

    # Chain SHA-256 blocks until we have enough bytes
    while len(seed_bytes) < n_bytes:
        extra = hashlib.sha256(
            seed_bytes[-32:] + len(seed_bytes).to_bytes(4, "big")
        ).digest()
        seed_bytes += extra

    # Trim exactly to what we need so unpack buffer matches precisely
    seed_bytes = seed_bytes[:n_bytes]
    assert len(seed_bytes) == n_bytes, f"Buffer mismatch: {len(seed_bytes)} != {n_bytes}"

    floats = struct.unpack(f"{n_params}f", seed_bytes)
    offset = 0
    with torch.no_grad():
        for param in model.parameters():
            size   = param.numel()
            tensor = torch.tensor(list(floats[offset:offset + size]), dtype=torch.float32)
            param.copy_(torch.tanh(tensor.reshape(param.shape)))
            offset += size


# ── Public API ─────────────────────────────────────────────────────────────────


def _build_model(password: str) -> tuple:
    """Return a (model, initial_hidden) pair seeded from password."""
    model = KeystreamGRU()
    _load_weights_from_password(model, password)
    model.eval()

    # Initial hidden state derived from password — needs HIDDEN_SIZE floats (64×4=256 bytes)
    # GRU hidden shape: (num_layers=1, batch=1, hidden_size=64)
    h_bytes = b""
    counter = 0
    needed  = HIDDEN_SIZE * 4  # 64 floats × 4 bytes = 256 bytes
    while len(h_bytes) < needed:
        h_bytes += hashlib.sha256(
            b"hidden:" + password.encode("utf-8") + counter.to_bytes(4, "big")
        ).digest()  # each call adds 32 bytes → 9 iterations covers 288 bytes
        counter += 1
    h_vals = struct.unpack(f"{HIDDEN_SIZE}f", h_bytes[:needed])
    hidden = torch.tanh(torch.tensor(list(h_vals), dtype=torch.float32).reshape(1, 1, HIDDEN_SIZE))
    return model, hidden


def _generate_keystream(model: KeystreamGRU, hidden: torch.Tensor, length: int) -> bytes:
    """Run the GRU autoregressively to produce `length` keystream bytes."""
    stream = bytearray()
    token  = torch.full((1, 1, 1), 0.5)

    with torch.no_grad():
        while len(stream) < length:
            out, hidden = model(token, hidden)

            val = out[0, 0, 0].item()

            # Guard against NaN/Inf from GRU numerical drift
            if not (val == val) or val != val or abs(val) == float("inf"):
                val = 0.5  # safe fallback — keeps keystream going

            # Clamp strictly to [0, 1] before converting to byte
            val = max(0.0, min(1.0, val))
            byte_val = int(val * 255.999)
            stream.append(byte_val & 0xFF)

            # Feed output back — replace NaN token with safe value to stop propagation
            token = out[:, -1:, :]
            if not torch.isfinite(token).all():
                token = torch.full_like(token, 0.5)

    return bytes(stream[:length])


def _argon2_pad(password: str, length: int) -> bytes:
    """
    Derive `length` bytes from the password via Argon2id + SHA-256 chaining.
    Uses a salt distinct from FIXED_SALT so this stream is independent of
    the weight-derivation stream.  Argon2id is memory-hard and GPU-resistant,
    consistent with every other engine in file2enc.
    """
    PAD_SALT = b"seq2enc-pad-v1"
    # Argon2id produces 32 bytes; chain with SHA-256 for longer payloads
    pad = _argon2_derive(password, PAD_SALT)  # 32 bytes
    while len(pad) < length:
        pad += hashlib.sha256(pad[-32:] + len(pad).to_bytes(4, "big")).digest()
    return pad[:length]


def seq2enc(data: bytes, password: str) -> bytes:
    """
    Encrypt or decrypt `data` using a GRU keystream derived from `password`.
    Calling this twice with the same password restores the original data.

    The GRU keystream is XORed with an Argon2id-derived pad so that password
    sensitivity is guaranteed even if the GRU converges to the same attractor
    for different weight initialisations.
    """
    if not data:
        return b""
    model, hidden = _build_model(password)
    gru_stream = _generate_keystream(model, hidden, len(data))
    pad_stream  = _argon2_pad(password, len(data))
    # Combined keystream: GRU ⊕ Argon2id-pad — still XOR-symmetric
    keystream = bytes(g ^ p for g, p in zip(gru_stream, pad_stream))
    return bytes(b ^ k for b, k in zip(data, keystream))