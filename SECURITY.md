# Security Policy

## Supported Engines

| Engine | Status | Safe for real data? |
|---|---|---|
| AES-256-GCM | ✅ Stable | Yes |
| AES-256-CBC | ✅ Stable | Yes |
| ChaCha20-Poly1305 | ✅ Stable | Yes |
| ECC (P-256/ECIES) | ✅ Stable | Yes |
| Signature (Biometric) | ⚠️ Experimental | No — see known limitations |
| Chameleon (Stego) | ⚠️ Experimental | No — see known limitations |
| Seq2Enc (GRU) | ❌ Demo only | Never |

## Threat Model

file2enc protects against:
- Unauthorized access to encrypted files at rest
- Tampering with vault files (detected via HMAC / AEAD tags)
- Brute-force attacks on passwords (PBKDF2, 480,000 iterations)

file2enc does **not** protect against:
- A compromised operating system or malware on your machine
- Memory forensics (Python cannot reliably zero memory)
- SSD wear-levelling retaining deleted file data
- An attacker who already has your password or private key
- Statistical steganalysis of Chameleon PNG files

## Known Limitations

**Signature engine:** The signature PNG is embedded inside the vault file.
An attacker with access to the vault can extract the image and use it to
derive the AES key directly, bypassing the biometric similarity check.
This engine is provided for demonstration purposes only.

**Seq2Enc engine:** Uses a GRU neural network as a keystream generator.
Neural networks are not cryptographically secure pseudorandom number
generators and have no security proof. Do not use for real data.

**Memory wiping:** Python's garbage collector may retain copies of
sensitive strings and bytes objects. The `crypto/secure.py` module
makes a best-effort attempt to zero memory via ctypes, but this is
not guaranteed across all Python implementations and platforms.

**Secure delete:** The 3-pass overwrite targets HDDs. On SSDs with
wear-levelling, the OS may write to different physical blocks, meaning
old data may persist. Full-disk encryption (e.g. BitLocker, FileVault)
is the strongest protection against this.

## Reporting a Vulnerability

If you discover a security vulnerability, please open a **private
GitHub Security Advisory** rather than a public issue:

GitHub repo → Security tab → "Report a vulnerability"

Please include:
- A description of the vulnerability
- Steps to reproduce
- Affected engine(s) or component(s)
- Suggested fix if you have one

We will respond within 7 days.
