"""
test/test_methods/test_engines.py
==================================
Unit tests for all file2enc encryption engines.

Run from project root:
    python3 -m pytest ./test/test_methods/test_engines.py -v
    python3 -m pytest ./test/test_methods/test_engines.py -v -k "not seq"   # skip slow GRU tests

Real files are loaded from the test/test_files/ directory automatically.
Synthetic fallback samples are used if a real file is not found.

Engines covered:
    aescbc   → AES-256-CBC + HMAC-SHA256
    aesgcm   → AES-256-GCM
    chacha   → ChaCha20-Poly1305
    ecc      → ECDH (P-256) + AES-256-GCM
    sig      → Biometric signature + AES-256-GCM
    chameleon→ LSB steganography + AES-256-GCM
    seq      → GRU neural keystream (experimental, slow)
"""

import os
import pytest
from pathlib import Path
from PIL import Image

# ── Engine imports ─────────────────────────────────────────────────────────────
from src.crypto.engines.engine_aescbc    import aescbc_encrypt,  aescbc_decrypt
from src.crypto.engines.engine_aesgcm    import aesgcm_encrypt,  aesgcm_decrypt
from src.crypto.engines.engine_chacha20  import chacha_encrypt,  chacha_decrypt
from src.crypto.engines.engine_ecc       import ecc_encrypt, ecc_decrypt, generate_keypair, load_public_key, load_private_key
from src.crypto.engines.engine_chameleon import chameleon_encrypt, chameleon_decrypt, cover_image_capacity
from src.crypto.engines.engine_seq2enc   import seq2enc
from src.crypto.vault import (
    encrypt_file, decrypt_file,
    METHOD_SEQ, METHOD_AESCBC, METHOD_AESGCM,
    METHOD_CHACHA, METHOD_ECC, METHOD_SIG, METHOD_CHAMELEON,
    SALT_SIZE,
)

TESTS_DIR = Path(__file__).parent.parent / "test_files"

# ── Load real test files, fall back to synthetic if missing ───────────────────

def _load(filename: str, fallback: bytes) -> bytes:
    p = TESTS_DIR / filename
    return p.read_bytes() if p.exists() else fallback

SAMPLES: dict[str, bytes] = {
    "txt":  _load("secret.txt",     b"Hello file2enc. This is a plain text test file.\n"),
    "py":   _load("sample_code.py", b"def hello():\n    print('file2enc test')\nhello()\n"),
    "jpg":  _load("ishowspeed.jpg",
                  b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"),
    "pdf":  _load("sample.pdf",
                  b"%PDF-1.4\n1 0 obj\n<</Type /Catalog>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n"),
    "png":  _load("sample.png",
                  b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                  b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
                  b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"),
    "docx": _load("sample.docx",
                  b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 20
                  + b"[Content_Types].xml" + b"\x00" * 64),
    "csv":  _load("sample.csv",
                  b"id,name,value\n1,alpha,100\n2,beta,200\n3,gamma,300\n"),
    "bin":  bytes(range(256)) * 4,
}

PASSWORDS = ["correct-horse-battery", "P@ssw0rd!", "12345", "日本語パスワード"]
WRONG_PW  = "definitely-wrong-password"


# ── Helpers ────────────────────────────────────────────────────────────────────

def vault_roundtrip(
    tmp_path: Path,
    ext: str,
    data: bytes,
    method: str,
    pw: str = "testpassword",
    pub_key_path: Path = None,
    priv_key_path: Path = None,
    cover_img_path: Path = None,
) -> bytes:
    """Encrypt data to a vault file, decrypt it, return decrypted bytes."""
    src = tmp_path / f"input.{ext}"
    enc = tmp_path / f"input.{ext}.vault"
    dec = tmp_path / f"output.{ext}"
    src.write_bytes(data)
    encrypt_file(src, enc, pw, method, pub_key_path=pub_key_path,
                 cover_img_path=cover_img_path)
    decrypt_file(enc, dec, pw, priv_key_path=priv_key_path,
                 cover_img_path=cover_img_path)
    return dec.read_bytes()


def make_cover_image(tmp_path: Path, w: int = 800, h: int = 600, name: str = "cover.png") -> Path:
    img  = Image.new("RGB", (w, h), color=(30, 120, 80))
    path = tmp_path / name
    img.save(str(path), format="PNG")
    return path

# ── Shared module-level ECC key pair ──────────────────────────────────────────

@pytest.fixture(scope="module")
def ecc_keypair(tmp_path_factory):
    base = tmp_path_factory.mktemp("keys")
    priv_path, pub_path = generate_keypair(base / "testkey")
    return priv_path, pub_path


# ══════════════════════════════════════════════════════════════════════════════
#  1. AES-256-CBC
# ══════════════════════════════════════════════════════════════════════════════

class TestAESCBC:

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_roundtrip(self, tmp_path, ext, data):
        assert vault_roundtrip(tmp_path, ext, data, "aescbc") == data

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_wrong_password_raises(self, tmp_path, ext, data):
        src = tmp_path / f"s.{ext}"; enc = tmp_path / f"s.vault"; dec = tmp_path / f"d.{ext}"
        src.write_bytes(data)
        encrypt_file(src, enc, "correct", "aescbc")
        with pytest.raises(Exception):
            decrypt_file(enc, dec, WRONG_PW)

    def test_empty_file(self, tmp_path):
        assert vault_roundtrip(tmp_path, "bin", b"", "aescbc") == b""

    def test_large_file(self, tmp_path):
        data = bytes(range(256)) * 1024 * 20   # ~5 MB
        assert vault_roundtrip(tmp_path, "bin", data, "aescbc", "bigpw") == data

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_unicode_passwords(self, tmp_path, pw):
        assert vault_roundtrip(tmp_path, "txt", b"sensitive", "aescbc", pw) == b"sensitive"

    def test_ciphertext_differs_from_plaintext(self, tmp_path):
        data = b"do not store plaintext" * 10
        src = tmp_path / "s.txt"; enc = tmp_path / "s.vault"
        src.write_bytes(data)
        encrypt_file(src, enc, "pw", "aescbc")
        assert enc.read_bytes() != data

    def test_two_encryptions_differ(self, tmp_path):
        src = tmp_path / "s.txt"
        e1  = tmp_path / "e1.vault"
        e2  = tmp_path / "e2.vault"
        src.write_bytes(b"same data every time")
        encrypt_file(src, e1, "pw", "aescbc")
        encrypt_file(src, e2, "pw", "aescbc")
        assert e1.read_bytes() != e2.read_bytes()

    def test_header_method_byte(self, tmp_path):
        src = tmp_path / "h.txt"; enc = tmp_path / "h.vault"
        src.write_bytes(b"header test")
        encrypt_file(src, enc, "pw", "aescbc")
        raw = enc.read_bytes()
        assert raw[:4] == b"F2EV"
        assert raw[5:6] == METHOD_AESCBC


# ══════════════════════════════════════════════════════════════════════════════
#  2. AES-256-GCM
# ══════════════════════════════════════════════════════════════════════════════

class TestAESGCM:

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_roundtrip(self, tmp_path, ext, data):
        assert vault_roundtrip(tmp_path, ext, data, "aesgcm") == data

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_wrong_password_raises(self, tmp_path, ext, data):
        src = tmp_path / f"s.{ext}"; enc = tmp_path / f"s.vault"; dec = tmp_path / f"d.{ext}"
        src.write_bytes(data)
        encrypt_file(src, enc, "correct", "aesgcm")
        with pytest.raises(Exception):
            decrypt_file(enc, dec, WRONG_PW)

    def test_empty_file(self, tmp_path):
        assert vault_roundtrip(tmp_path, "bin", b"", "aesgcm") == b""

    def test_large_file(self, tmp_path):
        data = bytes(range(256)) * 1024 * 20
        assert vault_roundtrip(tmp_path, "bin", data, "aesgcm", "bigpw") == data

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_unicode_passwords(self, tmp_path, pw):
        assert vault_roundtrip(tmp_path, "txt", b"sensitive", "aesgcm", pw) == b"sensitive"

    def test_header_method_byte(self, tmp_path):
        src = tmp_path / "h.txt"; enc = tmp_path / "h.vault"
        src.write_bytes(b"header test")
        encrypt_file(src, enc, "pw", "aesgcm")
        assert enc.read_bytes()[5:6] == METHOD_AESGCM


# ══════════════════════════════════════════════════════════════════════════════
#  3. ChaCha20-Poly1305
# ══════════════════════════════════════════════════════════════════════════════

class TestChaCha20:

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_roundtrip(self, tmp_path, ext, data):
        assert vault_roundtrip(tmp_path, ext, data, "chacha") == data

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_wrong_password_raises(self, tmp_path, ext, data):
        src = tmp_path / f"s.{ext}"; enc = tmp_path / f"s.vault"; dec = tmp_path / f"d.{ext}"
        src.write_bytes(data)
        encrypt_file(src, enc, "correct", "chacha")
        with pytest.raises(Exception):
            decrypt_file(enc, dec, WRONG_PW)

    def test_empty_file(self, tmp_path):
        assert vault_roundtrip(tmp_path, "bin", b"", "chacha") == b""

    def test_large_file(self, tmp_path):
        data = bytes(range(256)) * 1024 * 20
        assert vault_roundtrip(tmp_path, "bin", data, "chacha", "bigpw") == data

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_unicode_passwords(self, tmp_path, pw):
        assert vault_roundtrip(tmp_path, "txt", b"sensitive", "chacha", pw) == b"sensitive"

    def test_header_method_byte(self, tmp_path):
        src = tmp_path / "h.txt"; enc = tmp_path / "h.vault"
        src.write_bytes(b"header test")
        encrypt_file(src, enc, "pw", "chacha")
        assert enc.read_bytes()[5:6] == METHOD_CHACHA


# ══════════════════════════════════════════════════════════════════════════════
#  4. ECC (ECDH + AES-256-GCM)
# ══════════════════════════════════════════════════════════════════════════════

class TestECC:

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_roundtrip(self, tmp_path, ecc_keypair, ext, data):
        priv_path, pub_path = ecc_keypair
        assert vault_roundtrip(
            tmp_path, ext, data, "ecc",
            pub_key_path=pub_path,
            priv_key_path=priv_path,
        ) == data

    def test_wrong_key_raises(self, tmp_path, ecc_keypair):
        _, pub_path = ecc_keypair
        wrong_priv, _ = generate_keypair(tmp_path / "wrong")
        src = tmp_path / "s.txt"; enc = tmp_path / "s.vault"; dec = tmp_path / "d.txt"
        src.write_bytes(b"secret")
        encrypt_file(src, enc, "", "ecc", pub_key_path=pub_path)
        with pytest.raises(Exception):
            decrypt_file(enc, dec, "", priv_key_path=wrong_priv)

    def test_empty_file(self, tmp_path, ecc_keypair):
        priv_path, pub_path = ecc_keypair
        assert vault_roundtrip(
            tmp_path, "bin", b"", "ecc",
            pub_key_path=pub_path, priv_key_path=priv_path
        ) == b""

    def test_two_encryptions_differ(self, tmp_path, ecc_keypair):
        """ECC uses ephemeral keys — same plaintext must produce different ciphertext."""
        _, pub_path = ecc_keypair
        src  = tmp_path / "s.txt"
        enc1 = tmp_path / "e1.vault"
        enc2 = tmp_path / "e2.vault"
        src.write_bytes(b"forward secrecy check")
        encrypt_file(src, enc1, "", "ecc", pub_key_path=pub_path)
        encrypt_file(src, enc2, "", "ecc", pub_key_path=pub_path)
        assert enc1.read_bytes() != enc2.read_bytes()

    def test_header_method_byte(self, tmp_path, ecc_keypair):
        _, pub_path = ecc_keypair
        src = tmp_path / "h.txt"; enc = tmp_path / "h.vault"
        src.write_bytes(b"header test")
        encrypt_file(src, enc, "", "ecc", pub_key_path=pub_path)
        assert enc.read_bytes()[5:6] == METHOD_ECC

    def test_large_file(self, tmp_path, ecc_keypair):
        priv_path, pub_path = ecc_keypair
        data = bytes(range(256)) * 1024 * 5   # ~1.25 MB
        assert vault_roundtrip(
            tmp_path, "bin", data, "ecc",
            pub_key_path=pub_path, priv_key_path=priv_path,
        ) == data


# ══════════════════════════════════════════════════════════════════════════════
#  5. Chameleon (LSB steganography + AES-256-GCM)
# ══════════════════════════════════════════════════════════════════════════════

class TestChameleon:

    @pytest.mark.parametrize("ext,data", {
        "txt":  SAMPLES["txt"],
        "py":   SAMPLES["py"],
        "csv":  SAMPLES["csv"],
        "bin":  SAMPLES["bin"],
    }.items())
    def test_roundtrip(self, tmp_path, ext, data):
        cover = make_cover_image(tmp_path)
        salt  = os.urandom(16)
        cover_img = Image.open(str(cover)).convert("RGB")
        stego_img, png_info = chameleon_encrypt(data, f".{ext}", cover_img, salt)
        out = tmp_path / "stego.png"
        stego_img.save(str(out), format="PNG", pnginfo=png_info)
        stego_loaded = Image.open(str(out))
        decrypted, _ = chameleon_decrypt(stego_loaded, cover_img)
        assert decrypted == data

    def test_wrong_cover_raises(self, tmp_path):
        cover_orig  = make_cover_image(tmp_path, 800, 600, "cover_orig.png")
        cover_wrong = make_cover_image(tmp_path, 800, 600, "cover_wrong.png")      
        img = Image.open(str(cover_wrong))
        px  = img.load()
        px[0, 0] = (255, 0, 0)
        img.save(str(cover_wrong))

        salt      = os.urandom(16)
        cover_img = Image.open(str(cover_orig)).convert("RGB")
        wrong_img = Image.open(str(cover_wrong)).convert("RGB")
        data      = b"chameleon secret data"
        stego_img, png_info = chameleon_encrypt(data, ".txt", cover_img, salt)
        out = tmp_path / "stego.png"
        stego_img.save(str(out), format="PNG", pnginfo=png_info)
        stego_loaded = Image.open(str(out))
        with pytest.raises(ValueError):
            chameleon_decrypt(stego_loaded, wrong_img)

    def test_capacity_check_raises(self, tmp_path):
        """A 1×1 cover image cannot hold any meaningful payload."""
        tiny = Image.new("RGB", (1, 1), color=(0, 0, 0))
        salt = os.urandom(16)
        with pytest.raises(ValueError, match="too small"):
            chameleon_encrypt(b"A" * 100, ".txt", tiny, salt)

    def test_stego_png_has_metadata(self, tmp_path):
        """Output PNG must contain f2e_salt metadata."""
        cover = make_cover_image(tmp_path)
        salt  = os.urandom(16)
        cover_img = Image.open(str(cover)).convert("RGB")
        stego_img, png_info = chameleon_encrypt(b"test", ".txt", cover_img, salt)
        out = tmp_path / "stego.png"
        stego_img.save(str(out), format="PNG", pnginfo=png_info)
        loaded = Image.open(str(out))
        assert hasattr(loaded, "text")
        assert "f2e_salt" in loaded.text

    def test_cover_capacity_utility(self, tmp_path):
        """cover_image_capacity should return a non-empty string."""
        cover = make_cover_image(tmp_path, 1920, 1080)
        cap   = cover_image_capacity(cover)
        assert isinstance(cap, str)
        assert "MB" in cap

    def test_vault_pipeline_roundtrip(self, tmp_path):
        """End-to-end via encrypt_file / decrypt_file."""
        cover = make_cover_image(tmp_path, 800, 600)
        src   = tmp_path / "input.txt"
        dst   = tmp_path / "stego.cham.png"
        out   = tmp_path / "recovered.txt"
        data  = b"vault pipeline chameleon test"
        src.write_bytes(data)
        encrypt_file(src, dst, "", "chameleon", cover_img_path=cover)
        decrypt_file(dst, out, "", cover_img_path=cover)
        # decrypt_file may append the extension — search for any match
        candidates = list(tmp_path.glob("recovered*"))
        assert any(f.read_bytes() == data for f in candidates)


# ══════════════════════════════════════════════════════════════════════════════
#  6. Seq2Enc (GRU — experimental, marked slow)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
class TestSeq2Enc:
    """
    Marked @pytest.mark.slow — skip with:
        python -m pytest -v -k "not slow"
    """

    @pytest.mark.parametrize("ext,data", SAMPLES.items())
    def test_roundtrip_direct(self, ext, data):
        assert seq2enc(seq2enc(data, "pw"), "pw") == data

    def test_empty(self):
        assert seq2enc(b"", "pw") == b""

    def test_deterministic(self):
        data = b"determinism check"
        assert seq2enc(data, "pw") == seq2enc(data, "pw")

    def test_different_passwords_differ(self):
        data = b"same plaintext"
        assert seq2enc(data, "password_a") != seq2enc(data, "password_b")

    def test_ciphertext_differs_from_plaintext(self):
        data = b"plaintext must not survive" * 4
        assert seq2enc(data, "pw") != data

    def test_single_byte(self):
        for b in [b"\x00", b"\xff", b"Z"]:
            assert seq2enc(seq2enc(b, "pw"), "pw") == b

    @pytest.mark.parametrize("pw", PASSWORDS)
    def test_unicode_passwords(self, pw):
        data = b"unicode password test payload"
        assert seq2enc(seq2enc(data, pw), pw) == data

    def test_vault_roundtrip(self, tmp_path):
        data = SAMPLES["txt"]
        assert vault_roundtrip(tmp_path, "txt", data, "seq") == data

    def test_wrong_password_corrupts(self):
        data = b"secret data that should not be recovered"
        enc  = seq2enc(data, "correct")
        dec  = seq2enc(enc, WRONG_PW)
        assert dec != data

    def test_header_method_byte(self, tmp_path):
        src = tmp_path / "h.txt"; enc = tmp_path / "h.vault"
        src.write_bytes(b"header test")
        encrypt_file(src, enc, "pw", "seq")
        assert enc.read_bytes()[5:6] == METHOD_SEQ


# ══════════════════════════════════════════════════════════════════════════════
#  7. Vault format — shared edge cases
# ══════════════════════════════════════════════════════════════════════════════

class TestVaultFormat:

    def test_magic_bytes_present(self, tmp_path):
        src = tmp_path / "s.txt"; enc = tmp_path / "s.vault"
        src.write_bytes(b"magic test")
        encrypt_file(src, enc, "pw", "aesgcm")
        assert enc.read_bytes()[:4] == b"F2EV"

    def test_unknown_header_raises(self, tmp_path):
        enc = tmp_path / "bad.vault"
        enc.write_bytes(b"FAKE" + b"\x00" * 50)
        with pytest.raises(ValueError, match="Not a valid file2enc vault"):
            decrypt_file(enc, tmp_path / "out.bin", "pw")

    def test_truncated_file_raises(self, tmp_path):
        enc = tmp_path / "trunc.vault"
        enc.write_bytes(b"F2EV\x01\x03")   # too short
        with pytest.raises(ValueError):
            decrypt_file(enc, tmp_path / "out.bin", "pw")

    def test_tampered_header_raises(self, tmp_path):
        """Flipping the method byte must fail the header MAC check."""
        src = tmp_path / "s.txt"; enc = tmp_path / "s.vault"; dec = tmp_path / "d.txt"
        src.write_bytes(b"tamper test")
        encrypt_file(src, enc, "pw", "aesgcm")
        raw = bytearray(enc.read_bytes())
        raw[5] ^= 0xFF    # flip method byte
        enc.write_bytes(bytes(raw))
        with pytest.raises(ValueError, match="tampered|integrity|Unknown"):
            decrypt_file(enc, dec, "pw")

    @pytest.mark.parametrize("method", ["aescbc", "aesgcm", "chacha"])
    def test_empty_file_all_password_engines(self, tmp_path, method):
        assert vault_roundtrip(tmp_path, "bin", b"", method) == b""

    def test_non_vault_png_raises(self, tmp_path):
        """A plain PNG with no vault metadata must raise a clear error."""
        img = Image.new("RGB", (10, 10), color=(0, 0, 0))
        png = tmp_path / "plain.png"
        img.save(str(png))
        with pytest.raises(ValueError, match="not a Chameleon"):
            decrypt_file(png, tmp_path / "out.bin", "pw")