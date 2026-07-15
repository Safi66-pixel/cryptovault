# CryptoVault — Cross-Platform File Encryption Tool

A single-file Python CLI tool for encrypting/decrypting files on **Windows, macOS, and Linux**.

## How it protects your data

| Property | Implementation |
|---|---|
| Confidentiality | AES-256 in GCM mode |
| Integrity / tamper detection | GCM authentication tag (decryption fails loudly if the file was modified) |
| Password → key | scrypt (memory-hard KDF, resists GPU/brute-force cracking) |
| Randomness | Fresh random salt + nonce generated per file (never reused) |

There is **no backdoor or password recovery** — if you lose the password, the file cannot be recovered. That's the point.

## Setup (one-time, any OS)

```bash
pip install cryptography
```

That's the only dependency. Works identically on Windows, macOS, and Linux since it's pure Python.

## Usage

**Encrypt a file:**
```bash
python cryptovault.py encrypt secret.pdf
# -> creates secret.pdf.vault
```

**Decrypt a file:**
```bash
python cryptovault.py decrypt secret.pdf.vault
# -> creates secret.pdf
```

**Encrypt/decrypt an entire folder recursively:**
```bash
python cryptovault.py encrypt ./my_folder --recursive
python cryptovault.py decrypt ./my_folder --recursive
```

**Securely wipe the original after encrypting:**
```bash
python cryptovault.py encrypt secret.pdf --delete-original
```

**Custom output filename:**
```bash
python cryptovault.py decrypt secret.pdf.vault -o restored_secret.pdf
```

You'll be prompted for a password with hidden input (no echo to screen, no shell history).

## File format

```
MAGIC(4 bytes "CVLT") | VERSION(1) | SALT(16) | NONCE(12) | CIPHERTEXT+AUTH_TAG
```

## Notes / limitations

- `--delete-original` does a best-effort overwrite-before-delete. On SSDs and journaled/COW filesystems (most modern drives), wear-leveling means this is **not a forensic guarantee** — treat it as "better than a plain delete," not as secure erasure.
- Password strength is entirely on you — the tool warns on short passwords but doesn't enforce a policy. Use a long passphrase.
- This is a personal/portfolio-grade tool. For production or compliance-grade key management, look at proper KMS/HSM-backed solutions.
