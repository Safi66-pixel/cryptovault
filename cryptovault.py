#!/usr/bin/env python3
"""
CryptoVault - Cross-platform file encryption tool
====================================================
Works on Windows, macOS, and Linux (pure Python + `cryptography` package).

Security design:
  - AES-256-GCM (authenticated encryption -> confidentiality + integrity)
  - Key derived from a password using scrypt (memory-hard, brute-force resistant)
  - Random 16-byte salt and 12-byte nonce generated per file
  - Output file format (binary):
        MAGIC(4) | VERSION(1) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG(...)
  - Original filename is NOT leaked in the encrypted file name by default
    (you choose the output name), and file is only decrypted after the
    GCM authentication tag verifies -> tampering is detected and rejected.

Usage:
  Encrypt a single file:
      python cryptovault.py encrypt secret.pdf
      -> creates secret.pdf.vault

  Decrypt a single file:
      python cryptovault.py decrypt secret.pdf.vault
      -> creates secret.pdf  (or specify -o output_name)

  Encrypt/decrypt an entire folder recursively:
      python cryptovault.py encrypt ./my_folder --recursive
      python cryptovault.py decrypt ./my_folder --recursive

  Delete original file after successful encryption:
      python cryptovault.py encrypt secret.pdf --delete-original

You will be prompted for a password (hidden input). The SAME password
must be used to decrypt. There is no password recovery — if you forget
the password, the data is unrecoverable by design.
"""

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("ERROR: Missing dependency. Install it with:\n\n    pip install cryptography\n")
    sys.exit(1)

MAGIC = b"CVLT"          # file format magic bytes
VERSION = b"\x01"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32              # AES-256
DEFAULT_EXT = ".vault"

# scrypt cost parameters (tuned for ~0.3-0.5s on a modern machine;
# adjust N upward for more security at the cost of speed)
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(path: Path, password: str, output: Path, delete_original: bool = False) -> None:
    data = path.read_bytes()
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

    output.write_bytes(MAGIC + VERSION + salt + nonce + ciphertext)

    if delete_original:
        _secure_delete(path)

    print(f"  [+] Encrypted: {path}  ->  {output}")


def decrypt_file(path: Path, password: str, output: Path) -> None:
    blob = path.read_bytes()

    if len(blob) < len(MAGIC) + 1 + SALT_LEN + NONCE_LEN:
        raise ValueError("File too small / not a valid vault file")

    magic = blob[:4]
    version = blob[4:5]
    if magic != MAGIC:
        raise ValueError("Not a CryptoVault file (bad magic bytes)")
    if version != VERSION:
        raise ValueError(f"Unsupported vault version: {version}")

    salt = blob[5:5 + SALT_LEN]
    nonce = blob[5 + SALT_LEN:5 + SALT_LEN + NONCE_LEN]
    ciphertext = blob[5 + SALT_LEN + NONCE_LEN:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted/tampered file")

    output.write_bytes(plaintext)
    print(f"  [+] Decrypted: {path}  ->  {output}")


def _secure_delete(path: Path) -> None:
    """Best-effort overwrite-then-delete. Not guaranteed on SSDs/journaled FS,
    but better than a plain unlink for casual protection."""
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(length))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    path.unlink()


def collect_targets(target: Path, recursive: bool, mode: str):
    if target.is_file():
        return [target]
    if target.is_dir():
        if not recursive:
            print(f"'{target}' is a directory. Use --recursive to process it.")
            sys.exit(1)
        files = []
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if mode == "encrypt" and p.suffix == DEFAULT_EXT:
                continue
            if mode == "decrypt" and p.suffix != DEFAULT_EXT:
                continue
            files.append(p)
        return files
    print(f"Path not found: {target}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="CryptoVault - AES-256-GCM file encryption tool (cross-platform)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    for mode in ("encrypt", "decrypt"):
        p = sub.add_parser(mode, help=f"{mode} file(s)")
        p.add_argument("path", type=str, help="File or directory to process")
        p.add_argument("-o", "--output", type=str, default=None,
                        help="Output file path (single-file mode only)")
        p.add_argument("-r", "--recursive", action="store_true",
                        help="Recurse into directories")
        if mode == "encrypt":
            p.add_argument("--delete-original", action="store_true",
                            help="Securely delete the original file after encrypting")

    args = parser.parse_args()
    target = Path(args.path)

    files = collect_targets(target, args.recursive, args.mode)
    if not files:
        print("No matching files found.")
        return

    password = getpass.getpass("Password: ")
    if args.mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)
        if len(password) < 8:
            print("Warning: short passwords are weak. Consider 12+ characters / a passphrase.")

    print(f"\nProcessing {len(files)} file(s)...\n")

    for f in files:
        try:
            if args.mode == "encrypt":
                out = Path(args.output) if (args.output and len(files) == 1) else f.with_suffix(f.suffix + DEFAULT_EXT)
                encrypt_file(f, password, out, delete_original=args.delete_original)
            else:
                if args.output and len(files) == 1:
                    out = Path(args.output)
                else:
                    out = f.with_suffix("") if f.suffix == DEFAULT_EXT else Path(str(f) + ".decrypted")
                decrypt_file(f, password, out)
        except ValueError as e:
            print(f"  [!] Skipped {f}: {e}")
        except Exception as e:
            print(f"  [!] Error on {f}: {e}")

    print("\nDone.")


if __name__ == "__main__":
    main()
