# crypto/kdf.py — Key Derivation Function
#
# Argon2id — memory-hard, GPU-resistant, OWASP 2024 recommended
#
# Parameters (OWASP 2024):
#   memory      = 64 MB  (m=65536 KiB)
#   iterations  = 3      (t=3)
#   parallelism = 4      (p=4)
#   key length  = 32 bytes (256-bit)
#
# Requires: pip install argon2-cffi

from argon2.low_level import hash_secret_raw, Type

ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536   # 64 MB in KiB
ARGON2_PARALLELISM = 4
ARGON2_KEY_LENGTH  = 32


def derive_key(password: str, salt: bytes, length: int = ARGON2_KEY_LENGTH) -> bytes:
    """Derive a single key using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=length,
        type=Type.ID,
    )


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive two independent 256-bit keys from Argon2id output.
    Used by AES-256-CBC which needs separate enc + mac keys.
    Total output: 64 bytes, split into two 32-byte keys.
    """
    material = derive_key(password, salt, length=64)
    return material[:32], material[32:]