from hypothesis import given, settings
from hypothesis import strategies as st
from src.crypto.vault import decrypt_file
from pathlib import Path
import tempfile, os

@given(st.binary(min_size=0, max_size=512))
@settings(max_examples=500)
def test_decrypt_random_bytes_never_crashes(data):
    """Feeding random bytes to decrypt must never crash — only raise ValueError."""
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "bad.vault"
        dst = Path(tmp) / "out.bin"
        src.write_bytes(data)
        try:
            decrypt_file(src, dst, "password")
        except ValueError:
            pass   # expected — bad input should raise ValueError cleanly
        except Exception as e:
            raise AssertionError(f"Unexpected exception on random input: {e}")