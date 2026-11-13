#!/usr/bin/env python3
"""Encrypt a PostgreSQL custom-format backup before it leaves the host.

The key file is 32 random bytes. It must not be stored in the output directory.
This script does not upload anywhere and does not delete old backups.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"TSBK1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != 32:
        raise SystemExit("key file must be exactly 32 bytes")
    return key


def _refuse_shared_directory(key: Path, output: Path) -> None:
    if key.resolve().parent == output.resolve().parent:
        raise SystemExit("refusing to write ciphertext beside the key file")


def encrypt(source: Path, output: Path, key_path: Path, manifest: Path, revision: str, release: str, destination: str) -> None:
    _refuse_shared_directory(key_path, output)
    if output.exists() or manifest.exists():
        raise SystemExit("refusing to overwrite an existing backup")
    plaintext = source.read_bytes()
    if not plaintext.startswith(b"PGDMP"):
        raise SystemExit("input is not a PostgreSQL custom-format dump")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(key_path)).encrypt(nonce, plaintext, MAGIC)
    payload = MAGIC + nonce + ciphertext
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    body = {
        "created_at": datetime.now(UTC).isoformat(),
        "database_revision": revision,
        "application_release": release,
        "destination": destination,
        "encryption": "AES-256-GCM",
        "plaintext_sha256": _sha256(plaintext),
        "ciphertext_sha256": _sha256(payload),
        "plaintext_bytes": len(plaintext),
        "ciphertext_bytes": len(payload),
        "off_host": False,
    }
    manifest.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def decrypt(source: Path, output: Path, key_path: Path, manifest: Path) -> None:
    if output.exists():
        raise SystemExit("refusing to overwrite the restore target")
    payload = source.read_bytes()
    recorded = json.loads(manifest.read_text(encoding="utf-8"))
    if _sha256(payload) != recorded["ciphertext_sha256"]:
        raise SystemExit("ciphertext checksum does not match the manifest")
    if not payload.startswith(MAGIC) or len(payload) < len(MAGIC) + 12:
        raise SystemExit("backup header is not recognized")
    nonce = payload[len(MAGIC) : len(MAGIC) + 12]
    plaintext = AESGCM(_key(key_path)).decrypt(nonce, payload[len(MAGIC) + 12 :], MAGIC)
    if _sha256(plaintext) != recorded["plaintext_sha256"]:
        raise SystemExit("restored checksum does not match the manifest")
    output.write_bytes(plaintext)


def preview(directory: Path, days: int) -> None:
    cutoff = datetime.now(UTC).timestamp() - days * 86400
    print(f"retention preview only; nothing will be deleted; older than {days} days:")
    for path in sorted(directory.glob("*.manifest.json")):
        if path.stat().st_mtime < cutoff:
            print(path.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt or restore a PostgreSQL custom-format backup")
    parser.add_argument("action", choices=("encrypt", "decrypt", "retention-preview", "dry-run"))
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--key")
    parser.add_argument("--manifest")
    parser.add_argument("--revision", default="unknown")
    parser.add_argument("--release", default="unknown")
    parser.add_argument("--destination", default="local-drill")
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()
    if args.action == "retention-preview":
        preview(Path(args.input or "."), args.days)
        return
    if args.action == "dry-run":
        print("dry-run: no file will be written and no upload will be attempted")
        print(f"action=encrypt input={args.input or '-'} destination={args.destination}")
        return
    if not args.input or not args.output or not args.key:
        raise SystemExit("input, output, and key are required")
    source = Path(args.input)
    output = Path(args.output)
    key = Path(args.key)
    manifest = Path(args.manifest) if args.manifest else output.with_suffix(output.suffix + ".manifest.json")
    if args.action == "encrypt":
        encrypt(source, output, key, manifest, args.revision, args.release, args.destination)
        print(f"encrypted {output.name}; manifest {manifest.name}; not uploaded")
        return
    decrypt(source, output, key, manifest)
    print(f"restored {output.name}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit("backup command failed")
