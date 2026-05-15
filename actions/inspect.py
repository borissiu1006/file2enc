# actions/inspect.py

from pathlib import Path
from ui.colors import ask, ok, err, info, c, CYAN, DIM, YELLOW, GREEN, RED, WHITE, BOLD, ORANGE

VAULT_MAGIC     = b"F2EV"
PNG_MAGIC       = b"\x89PNG"
HEADER_SIZE     = 4 + 1 + 1 + 16        # magic + version + method + salt = 22
HEADER_MAC_SIZE = 32
PAYLOAD_OFFSET  = HEADER_SIZE + HEADER_MAC_SIZE  # 54

METHOD_NAMES = {
    b'\x01': ("AES-256-GCM",        "password"),
    b'\x02': ("AES-256-CBC",        "password"),
    b'\x03': ("ChaCha20-Poly1305",  "password"),
    b'\x04': ("ECC (P-256/ECIES)",  "private key (.priv.pem)"),
    b'\x05': ("Seq2Enc (GRU)",      "password"),
    b'\x06': ("Signature",          "drawn signature"),
}


def _row(label: str, value: str, color=CYAN):
    pad = 16
    print(c(f"  {label:<{pad}}", DIM) + c(value, color))


def action_inspect():
    info("Inspect a file2enc vault or Chameleon PNG")
    src = Path(ask("File path"))
    if not src.is_file():
        err(f"File not found: {src}"); return

    raw  = src.read_bytes()
    size = src.stat().st_size

    print()
    _row("File", str(src.resolve()), WHITE)
    _row("Size", f"{size:,} bytes ({size / 1024:.1f} KB)")

    # ── Chameleon PNG ──────────────────────────────────────────────────────────
    if raw[:4] == PNG_MAGIC:
        _row("Format", "Chameleon PNG (steganographic)", ORANGE)
        try:
            from PIL import Image
            img  = Image.open(str(src))
            meta = getattr(img, "text", {})
            w, h = img.size

            _row("Dimensions", f"{w} × {h} px")

            if "f2e_salt" in meta:
                _row("Salt", meta["f2e_salt"], DIM)
                _row("Version", meta.get("f2e_ver", "unknown"))
                _row("Engine", "AES-256-GCM + LSB steganography")
                _row("Key source", "cover image pixel fingerprint")
                _row("Status", "valid Chameleon vault ✔", GREEN)
            else:
                _row("Status", "PNG has no file2enc metadata — not a Chameleon vault ✘", RED)
        except Exception as e:
            _row("Status", f"could not read PNG: {e}", RED)
        return

    # ── Standard F2EV vault ────────────────────────────────────────────────────
    if raw[:4] != VAULT_MAGIC:
        _row("Format", "unknown — not a file2enc vault", RED)
        _row("First bytes", raw[:8].hex(), DIM)
        err("This does not look like a file2enc file.")
        return

    _row("Format", "file2enc vault (F2EV)")

    if size < PAYLOAD_OFFSET:
        _row("Status", "file too short — truncated or corrupted ✘", RED)
        return

    version    = raw[4]
    method_b   = raw[5:6]
    salt       = raw[6:6 + 16]
    stored_mac = raw[HEADER_SIZE:HEADER_SIZE + HEADER_MAC_SIZE]
    payload    = raw[PAYLOAD_OFFSET:]
    header     = raw[:HEADER_SIZE]

    _row("Version", f"0x{version:02X} ({'Argon2id' if version == 0x02 else 'PBKDF2' if version == 0x01 else 'unknown'})")

    # Method
    if method_b in METHOD_NAMES:
        engine, key_source = METHOD_NAMES[method_b]
        _row("Method", f"0x{method_b.hex().upper()}  {engine}")
        _row("Key source", key_source)
    else:
        _row("Method", f"0x{method_b.hex().upper()}  unknown", YELLOW)

    _row("Salt", salt.hex(), DIM)
    _row("Header MAC", stored_mac[:16].hex() + "…", DIM)
    _row("Payload", f"{len(payload):,} bytes")

    # Verify header MAC
    try:
        import hmac as _hmac, hashlib
        HEADER_DOMAIN  = b"file2enc-header-mac-v1"
        payload_sample = (payload[:32] + b"\x00" * 32)[:32]
        domain_padded  = (HEADER_DOMAIN + b"\x00" * 32)[:32]
        mac_key        = bytes(a ^ b for a, b in zip(payload_sample, domain_padded))
        expected_mac   = _hmac.new(mac_key, header, hashlib.sha256).digest()

        if _hmac.compare_digest(stored_mac, expected_mac):
            _row("Header MAC", "verified ✔", GREEN)
        else:
            _row("Header MAC", "FAILED — header may be tampered or corrupted ✘", RED)
    except Exception as e:
        _row("Header MAC", f"could not verify: {e}", YELLOW)

    _row("Status", "valid file2enc vault ✔", GREEN)