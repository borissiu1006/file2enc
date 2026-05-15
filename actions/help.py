# actions/help.py

from ui.colors import c, CYAN, GREEN, WHITE, BOLD, DIM, ORANGE


def action_help():
    print(c("""
  File2Enc — Multi-Engine File Encryption Tool
  ─────────────────────────────────────────────────────────────────
""", GREEN, BOLD))

    # ── How it works ───────────────────────────────────────────────────────────
    print(c("  HOW IT WORKS\n", WHITE, BOLD))
    print(c(
        "  Every encrypted file (except Chameleon) is saved as a .vault file:\n"
        "\n"
        "      [ Method (1 byte) | Salt (16 bytes) | Engine payload ]\n"
        "\n"
        "  The method byte tells the decryptor which engine was used.\n"
        "  The salt is random per file — never reused.\n"
        "  Your password is never stored — only a derived key is used.\n"
        "\n"))

    # ── Engines ────────────────────────────────────────────────────────────────
    print(c("  ENCRYPTION ENGINES\n", WHITE, BOLD))

    engines = [
        (
            "1", "AES-256-GCM", "Recommended ✦",
            "AES in Galois/Counter Mode — encryption and authentication in a\n"
            "     single pass. Fast, modern, and detects any tampering at\n"
            "     decryption time. PBKDF2-SHA256, 480 000 iterations."
        ),
        (
            "2", "AES-256-CBC", "Widely supported",
            "Industry-standard block cipher in CBC mode with Encrypt-then-MAC.\n"
            "     Two keys are derived: one for AES-256-CBC, one for HMAC-SHA256\n"
            "     authentication. PBKDF2-SHA256, 480 000 iterations."
        ),
        (
            "3", "ChaCha20-Poly1305", "Best on mobile / no hardware AES",
            "Stream cipher by Daniel J. Bernstein. Preferred over AES on\n"
            "     devices lacking hardware AES acceleration (older ARM, etc.).\n"
            "     Poly1305 provides authentication. PBKDF2-SHA256, 480 000 iterations."
        ),
        (
            "4", "ECC  (P-256 / ECIES)", "Public-key, no shared password",
            "Hybrid encryption: ephemeral ECDH produces a shared secret;\n"
            "     HKDF-SHA256 derives an AES-256-GCM key from it. Encrypt with\n"
            "     a public key (.pub.pem); decrypt with the private key (.priv.pem).\n"
            "     The program can generate a key pair for you. A new ephemeral\n"
            "     key is used every encryption for forward secrecy."
        ),
        (
            "5", "Seq2Enc  (GRU)", "! Experimental",
            "A GRU neural network acts as a keystream generator. Network weights\n"
            "     are derived entirely from your password via PBKDF2, making it\n"
            "     fully deterministic. The keystream is XOR'd with your file.\n"
            "     Encrypting twice with the same password restores the original."
        ),
        (
            "6", "Signature  (Biometric)", "! Fun — draw to lock, draw to unlock",
            "Your handwritten signature is captured in a pop-up window and used\n"
            "     as the key: SHA-256(pixels) → HKDF → AES-256-GCM. On decryption,\n"
            "     similarity is scored via SSIM (40 %) + MobileNetV2 cosine (60 %).\n"
            "     A 70 % match is required to unlock."
        ),
        (
            "7", "Chameleon  (Steganography)", "! Fun — hide a file inside an image",
            "Your file is AES-256-GCM encrypted then hidden inside a cover image\n"
            "     using 2-bit LSB steganography (max ±3 per RGB channel — invisible\n"
            "     to the eye). The cover image's pixel fingerprint is the key;\n"
            "     without the exact original image decryption is impossible.\n"
            "     Output is a fully valid, openable PNG file."
        ),
    ]

    for num, name, tag, desc in engines:
        print(
            c(f"  {num}.  {name}", ORANGE, BOLD) + "  " +
            c(tag, CYAN)
        )
        print(c(f"     {desc}\n", DIM))

    # ── Workflow ───────────────────────────────────────────────────────────────
    print(c("  WORKFLOW\n", WHITE, BOLD))
    print(c(
        "  Encrypt:\n"
        "    1. Select 'Encrypt a file' from the menu.\n"
        "    2. Enter the source file path (any file type supported).\n"
        "    3. Choose an engine (1–7).\n"
        "    4. Provide the required secret — password, key pair, signature,\n"
        "       or cover image depending on the engine.\n"
        "    5. A .vault file is created (or a .png for Chameleon).\n"
        "    6. Optionally securely delete the original (3× overwrite + unlink).\n"
        "\n"
        "  Decrypt:\n"
        "    1. Select 'Decrypt a file' from the menu.\n"
        "    2. Enter the encrypted file path.\n"
        "    3. The engine is detected automatically from the file.\n"
        "    4. Provide the same secret used during encryption.\n"
        "    5. The original file is restored with its original extension.\n"
        "\n"
        "  Inspect:\n"
        "    Shows the method byte, salt hex, and validity of any .vault file.\n",
    CYAN))

    # ── Tips ───────────────────────────────────────────────────────────────────
    print(c("  TIPS\n", WHITE, BOLD))
    print(c(
        "  • AES-256-GCM (1) is the best choice for everyday use.\n"
        "  • Use ECC (4) to encrypt a file for someone else using their public key.\n"
        "  • Use Chameleon (7) when you want the encrypted file to look like a photo.\n"
        "  • The secure delete option overwrites the original file 3 times before\n"
        "    unlinking it. Note: SSDs with wear-levelling may retain residual data.\n"
        "    Full-disk encryption is the strongest guarantee against recovery.\n"
        "  • For Chameleon: keep the original cover image safe — it is the only\n"
        "    key. Losing it means losing your file permanently.\n"
        "  • Never share your password or private key over insecure channels.\n",
    CYAN))