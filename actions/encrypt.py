# actions/encrypt.py

from pathlib import Path
from ui.colors import ask, ok, err, info, c, WHITE, BOLD, DIM, CYAN, YELLOW, GREEN
from crypto.secure import wipe_bytes

ENGINES = {
    "1": ("aesgcm",    "AES-256-GCM          — ✦ Recommended -- Fast with built-in authentication "),
    "2": ("aescbc",    "AES-256-CBC          — Widely supported, safe for local files"),
    "3": ("chacha",    "ChaCha20-Poly1305    — Best on mobile / no hardware AES"),
    "4": ("ecc",       "ECC (P-256/ECIES)    — Public-key encryption, no shared password"),
    "5": ("seq",       "Seq2Enc (GRU)        — ! Experimental -- ML neural keystream"),
    "6": ("sig",       "Signature (Biometric)— ! Fun engine -- Use your signature as the key"),
    "7": ("chameleon", "Chameleon (Stego)    — ! Fun engine --Hide file inside a cover image"),
}


def action_encrypt():
    info("Encrypt a file")
    src = Path(ask("Source file path"))
    if not src.is_file():
        err(f"File not found: {src}"); return

    print(f"\n  {c('Choose encryption engine:', WHITE, BOLD)}\n")
    for num, (_, label) in ENGINES.items():
        print(f"    {c(num + '.', CYAN, BOLD)}  {label}")
    print()

    choice = ask("Select engine [1-7]").strip()
    if choice not in ENGINES:
        err("Invalid choice."); return
    method, label = ENGINES[choice]
    print(f"  {c('Using:', DIM)} {label.split('—')[0].strip()}\n")

    pub_key_path   = None
    password       = ""
    sig_img        = None
    cover_img_path = None

    if method == "ecc":
        print(f"\n  {c('ECC Key Setup:', WHITE, BOLD)}\n")
        print(f"    {c('1.', CYAN, BOLD)}  Generate a new key pair now")
        print(f"    {c('2.', CYAN, BOLD)}  Use an existing public key (.pub.pem)")
        print()
        key_choice = ask("Select [1/2]").strip()

        if key_choice == "1":
            from crypto.engine_ecc import generate_keypair
            stem_raw = ask("Key name stem [mykey]")
            stem = Path(stem_raw) if stem_raw else Path("mykey")
            try:
                priv_path, pub_path = generate_keypair(stem)
                ok(f"Private key saved → {priv_path}")
                ok(f"Public  key saved → {pub_path}")
                print(c(f"\n  Keep {priv_path.name} secret — you will need it to decrypt.\n", YELLOW))
                pub_key_path = pub_path
            except Exception as e:
                err(f"Key generation failed: {e}"); return
        elif key_choice == "2":
            pub_raw = ask("Public key file (.pub.pem)")
            pub_key_path = Path(pub_raw)
            if not pub_key_path.is_file():
                err(f"Public key not found: {pub_key_path}"); return
        else:
            err("Invalid choice."); return

    elif method == "sig":
        from ui.sig_canvas import capture_signature
        print(c("\n  A window will open — draw your signature to use as the encryption key.\n", YELLOW))
        sig_img = capture_signature("Draw your signature, then click Confirm.")
        if sig_img is None:
            err("Signature cancelled. Encryption aborted."); return
        ok("Signature captured.")

    elif method == "chameleon":
        print(f"\n  {c('Chameleon Setup:', WHITE, BOLD)}\n")
        print(c("  Your file will be hidden inside a cover image.", CYAN))
        print(c("  The cover image itself becomes the decryption key.\n", CYAN))

        cover_raw = ask("Cover image path (.jpg / .png)")
        cover_img_path = Path(cover_raw)
        if not cover_img_path.is_file():
            err(f"Cover image not found: {cover_img_path}"); return
        if cover_img_path.suffix.lower() not in (".jpg", ".jpeg", ".png", ".bmp", ".tiff"):
            err("Cover image must be a JPG, PNG, BMP, or TIFF file."); return

        try:
            from crypto.engine_chameleon import cover_image_capacity
            cap_str = cover_image_capacity(cover_img_path)
            print(c(f"\n  Cover capacity : {cap_str}", GREEN))
        except Exception:
            pass

        file_size = src.stat().st_size
        print(c(f"  File to hide   : {file_size:,} bytes ({file_size / 1024:.1f} KB)\n", DIM))
        print(c(
            "  ⚠  Keep the original cover image safe — you will need it\n"
            "     to decrypt. Loss of the cover image = loss of your file.\n",
            YELLOW
        ))

    else:
        password = ask("Password", secret=True)
        pw2      = ask("Confirm password", secret=True)
        if password != pw2:
            err("Passwords do not match."); return

    # ── Output path ────────────────────────────────────────────────────────────
    default_dst = (
        src.with_suffix(".cham.png") if method == "chameleon"
        else src.with_suffix(src.suffix + ".vault")
    )
    dst_raw = ask(f"Output file path [{default_dst}]")
    dst = Path(dst_raw) if dst_raw else default_dst

    # ── Encrypt ────────────────────────────────────────────────────────────────
    raw_data = None
    try:
        from crypto.vault import encrypt_file
        encrypt_file(src, dst, password, method, pub_key_path, sig_img, cover_img_path)
        ok(f"Encrypted ({label.split('—')[0].strip()}) → {dst}")

        if method == "chameleon":
            print(c(
                f"\n  The file is now hidden inside {dst.name}.\n"
                f"  To decrypt, you will need:\n"
                f"    • This PNG file\n"
                f"    • The original cover image: {cover_img_path.name}",
                CYAN
            ))

    except Exception as e:
        err(f"Encryption failed: {e}")
        return

    # ── Secure delete original ─────────────────────────────────────────────────
    print()
    confirm = ask(
        c("Securely delete the original file? Overwrite 3× then unlink [y/N]", YELLOW)
    ).strip().lower()

    if confirm == "y":
        from crypto.secure import secure_delete
        try:
            secure_delete(src)
            ok(f"Original securely deleted: {src.name}")
            print(c(
                "  Note: SSD wear-levelling may retain residual data.\n"
                "  Full-disk encryption is the strongest guarantee.", DIM
            ))
        except Exception as e:
            err(f"Secure delete failed: {e}")
    else:
        print(c(f"\n  Original file kept at: {src}", DIM))

    # ── Wipe plaintext from memory (best-effort) ───────────────────────────────
    if password:
        wipe_bytes(password.encode())