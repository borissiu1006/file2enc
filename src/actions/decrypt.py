# actions/decrypt.py

from pathlib import Path
from src.ui.colors import ask, ok, err, info, c, YELLOW, CYAN, DIM
from src.crypto.secure import wipe_bytes

# Method bytes defined locally — must stay in sync with crypto/vault.py.
# Matches encrypt.py menu order exactly.
METHOD_AESGCM = b'\x01'
METHOD_AESCBC = b'\x02'
METHOD_CHACHA = b'\x03'
METHOD_ECC    = b'\x04'
METHOD_SEQ    = b'\x05'
METHOD_SIG    = b'\x06'
PNG_MAGIC     = b"\x89PNG"
VAULT_MAGIC   = b"F2EV"

# New vault header: magic(4) + version(1) + method(1) + salt(16) + mac(32) = 54 bytes
PAYLOAD_OFFSET = 4 + 1 + 1 + 16 + 32   # 54


def action_decrypt():
    info("Decrypt a file")
    src = Path(ask("Encrypted file path"))
    if not src.is_file():
        err(f"File not found: {src}"); return

    raw = src.read_bytes()

    priv_key_path  = None
    password       = ""
    sig_img        = None
    cover_img_path = None

    # ── Detect vault type ──────────────────────────────────────────────────────
    is_chameleon = (raw[:4] == PNG_MAGIC)
    is_vault     = (raw[:4] == VAULT_MAGIC)
    is_ecc       = (is_vault and raw[5:6] == METHOD_ECC)
    is_sig       = (is_vault and raw[5:6] == METHOD_SIG)

    if is_chameleon:
        print(c(
            "\n  Chameleon PNG detected.\n"
            "  You need the exact original cover image used during encryption.\n",
            CYAN
        ))
        cover_raw = ask("Original cover image path")
        cover_img_path = Path(cover_raw)
        if not cover_img_path.is_file():
            err(f"Cover image not found: {cover_img_path}"); return

    elif not is_vault:
        err("Unrecognised file format — not a file2enc vault or Chameleon PNG."); return

    elif is_ecc:
        priv_raw = ask("Private key file (.priv.pem)")
        priv_key_path = Path(priv_raw)
        if not priv_key_path.is_file():
            err(f"Private key not found: {priv_key_path}"); return

    elif is_sig:
        from src.ui.sig_canvas import capture_signature
        from src.crypto.engines.engine_sig import get_similarity
        print(c("\n  A window will open — draw your signature to unlock the file.\n", YELLOW))
        sig_img = capture_signature("Draw your signature to decrypt, then click Confirm.")
        if sig_img is None:
            err("Signature cancelled. Decryption aborted."); return

        try:
            payload = raw[PAYLOAD_OFFSET:]
            score   = get_similarity(payload, sig_img)
            if score >= 0.70:
                ok(f"Signature match: {score:.1%} — unlocking...")
            else:
                err(f"Signature mismatch: {score:.1%} (need 70%). Decryption denied.")
                return
        except Exception:
            pass   # let decrypt_file raise the proper error

    else:
        password = ask("Password", secret=True)

    # ── Output path ────────────────────────────────────────────────────────────
    if is_chameleon:
        stem = src.stem
        if stem.endswith(".cham"):
            stem = stem[:-5]
        default_dst = src.parent / stem
    elif src.suffix == ".vault":
        default_dst = src.with_suffix("")
    else:
        default_dst = src.with_suffix(".decrypted")

    dst_raw = ask(f"Output path [{default_dst}]")
    dst = Path(dst_raw) if dst_raw else default_dst

    # ── Decrypt ────────────────────────────────────────────────────────────────
    try:
        from src.crypto.vault import decrypt_file
        decrypt_file(src, dst, password, priv_key_path, sig_img, cover_img_path)

        if is_chameleon and not dst.exists():
            candidates = list(dst.parent.glob(dst.name + ".*"))
            ok(f"Decrypted → {candidates[0]}") if candidates else ok(f"Decrypted → {dst}")
        else:
            ok(f"Decrypted → {dst}")

    except ValueError as e:
        err(str(e)); return
    except Exception as e:
        err(f"Decryption failed: {e}"); return
    finally:
        if password:
            wipe_bytes(password.encode())

    # ── Wipe decrypted bytes from memory after writing ─────────────────────────
    try:
        written = dst.read_bytes() if dst.exists() else b""
        wipe_bytes(written)
    except Exception:
        pass