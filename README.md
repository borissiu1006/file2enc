# file2enc 

A CLI file encryption tool with multiple encryption engines. Some of them are really secure (e.g. aes, chacha20, ecc), some are originated from my ideas when I imagine how can we encrypt/decrypt files.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

| Engine | Algorithm | Auth method |
|---|---|---|
| AES-256-GCM | AES-256-GCM | Password |
| AES-256-CBC | AES-256-CBC + HMAC-SHA256 | Password |
| ChaCha20-Poly1305 | ChaCha20-Poly1305 | Password |
| ECC | ECDH (P-256) + AES-256-GCM | Key pair (.pem) |
| Signature *(fun)*| AES-256-GCM | Draw signature |
| Chameleon *(fun)*| AES-256-GCM + LSB steganography | Cover image |
| Seq2Enc *(experimental)* | GRU neural keystream XOR | Password |

- Arrow-key navigable terminal UI
- Vault format with magic bytes, versioning, and header integrity (HMAC)
- Secure file deletion (3-pass overwrite + fsync)
- Cross-platform: Windows & macOS

---

## ⚠️ Security Disclaimer

> **No professional security audit has been performed on file2enc.**
> - This tool is aimed for regular users' daily use. It is not professional enough for corporates/ organizations to handle sensitive data.
> - ! For production use, do not use any fun/experimental engines (**Seq2Enc**, **Signature**, **Chameleon**). Use **AES-256-GCM**, **ChaCha20-Poly1305** or **ECC** only.

**Flaws on Fun/Experimental Engines**
> - The **Seq2Enc** engine uses a GRU neural network as a keystream generator. It has no cryptographic security proof and should **never** be used for real sensitive data.
> - The **Signature** engine is experimental. The signature image is embedded in the vault, which has design implications for key security.
> - For **Chameleon**, well it's actually pretty secure and is a perfect disguise for hiding data!

This project has been scanned with:
- [Bandit](https://bandit.readthedocs.io) — Python static security analysis
- [pip-audit](https://pypi.org/project/pip-audit) — dependency CVE scanning

This is **not** a substitute for a professional security audit.
See [SECURITY.md](SECURITY.md) for detailed known limitations.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/file2enc.git
cd file2enc
pip install -r requirements.txt
python main.py
```

### Requirements

```
cryptography
pillow
numpy
torch
torchvision
scikit-image
```

Or install all at once:

```bash
pip install -r requirements.txt
```

---

## Project Structure

```
file2enc/
├── main.py                  ← Entry point
├── requirements.txt
├── ui/
│   ├── banner.py            ← ASCII pixel art banner
│   ├── menu.py              ← Arrow-key navigable menu
│   ├── colors.py            ← ANSI color helpers
│   ├── theme.py             ← Shared hex color constants
│   └── sig_canvas.py        ← Tkinter signature drawing window
├── crypto/
│   ├── crypto/kdf.py  ← single place for all KDF logic
│   │       ├── derive_key_argon2()    ← V2, new vaults
│   │       ├── derive_keys_argon2()   ← V2, AES-CBC (needs 2 keys)
│   │       ├── derive_key_pbkdf2()    ← V1, legacy read-only
│   │       └── derive_keys_pbkdf2()   ← V1, AES-CBC legacy
│   ├── vault.py             ← Vault format dispatcher
│   ├── secure.py            ← Secure delete & memory wipe
│   ├── engine_aesgcm.py
│   ├── engine_aescbc.py
│   ├── engine_chacha20.py
│   ├── engine_ecc.py
│   ├── engine_sig.py.       ← Fun engine
│   ├── engine_chameleon.py. ← Fun engine
│   └── engine_seq2enc.py    ← Experimental
├── actions/
│   ├── encrypt.py
│   ├── decrypt.py
│   ├── inspect.py
│   └── help.py
└── tests/
    └── test_engines.py
```

---

## Vault Format

All non-Chameleon engines write a structured binary vault:

```
[ Magic "F2EV" (4B) | Version (1B) | Method (1B) | Salt (16B) | Header MAC (32B) | Payload ]
```

- **Magic + Version** — detect format mismatches early
- **Header MAC** — HMAC-SHA256 over the header, detects tampering with method or salt bytes
- **Payload** — authenticated by each engine's own AEAD tag or HMAC

---

## Usage

```bash
python main.py
```

Navigate with ↑ ↓ arrow keys, press Enter to select, or type the item number.

### Encrypt a file

```
Encrypt a file → choose engine → enter password (or key/signature) → done
```

After encryption you are offered the option to **securely delete** the original (3-pass overwrite).

### Decrypt a file

```
Decrypt a file → provide the vault file → enter password (or key/signature)
```

### ECC workflow

```bash
# 1. Encrypt — choose ECC → generate key pair → mykey.pub.pem + mykey.priv.pem
# 2. Decrypt — provide mykey.priv.pem
```

### Chameleon workflow

```bash
# 1. Encrypt — choose Chameleon → provide a cover image → output is a .cham.png
# 2. Decrypt — provide the .cham.png + the original cover image
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/test_engines.py -v
```

---

## License

MIT — see [LICENSE](LICENSE).
# file2enc
An encryption tool with several engines that safely encrypt your files.
