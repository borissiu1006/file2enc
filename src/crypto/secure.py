# crypto/secure.py — Secure file deletion and best-effort memory wiping
#
# Secure delete: overwrites file bytes with random data before unlinking,
# making simple forensic recovery significantly harder.
# Note: SSDs with wear-levelling and filesystem journaling mean overwrite-based
# deletion is never a 100% guarantee — full-disk encryption is the gold standard.
#
# Memory wiping: Python does not allow explicit memory zeroing of str/bytes
# objects (the GC may keep copies). We use ctypes to zero the internal buffer
# of bytearray objects where possible, and note the limitation for str/bytes.

import os
import ctypes
from pathlib import Path


# ── Secure file deletion ───────────────────────────────────────────────────────

def secure_delete(path: Path, passes: int = 3) -> None:
    """
    Overwrite a file with random bytes `passes` times, then delete it.
    Works on all platforms. Does NOT guarantee deletion on SSDs.

    Args:
        path   : file to delete
        passes : number of overwrite passes (default 3 — DoD 5220.22-M basic)
    """
    path = Path(path)
    if not path.is_file():
        return

    size = path.stat().st_size
    if size == 0:
        path.unlink()
        return

    try:
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())   # force kernel buffer flush to disk
    except OSError:
        pass   # best-effort — still unlink below

    path.unlink()


# ── Memory wiping ──────────────────────────────────────────────────────────────

def wipe_bytearray(buf: bytearray) -> None:
    """
    Zero the contents of a bytearray in-place using ctypes.
    This is the only reliable way to wipe memory in Python.
    """
    if not isinstance(buf, bytearray) or len(buf) == 0:
        return
    addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
    ctypes.memset(addr, 0, len(buf))


def wipe_bytes(data: bytes) -> None:
    """
    Best-effort wipe of a bytes object.
    WARNING: bytes are immutable and interned — Python may keep copies.
    We cast via ctypes and zero the underlying buffer, but this is NOT
    guaranteed to reach all copies. Use bytearray where security matters.
    """
    if not data:
        return
    try:
        addr = id(data) + 32    # CPython bytes object header offset (ob_val)
        ctypes.memset(addr, 0, len(data))
    except Exception:
        pass   # non-CPython runtimes — silently skip