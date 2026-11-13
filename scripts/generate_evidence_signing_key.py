#!/usr/bin/env python3
"""Generate a reference Ed25519 signing key without printing private key material.

Supported invocation: run inside the production threatsight-api image (see
docs/reference/runbooks/evidence-signing.md). Host python3 is not assumed to have
ThreatSight, pydantic, or cryptography installed.

Writes:
  <dir>/ed25519-private.pem  (mode 0400)
  <dir>/ed25519-public.pem   (mode 0444)
  <dir>/ed25519.fingerprint  (public fingerprint only)

Does not overwrite existing files. Does not print private key bytes.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

# Allow running from repo root without install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/api/src"))

from threatsight_api.signing.provider import generate_ed25519_keypair_files  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default="/var/lib/threatsight/evidence-signing",
        help="Destination directory (default: /var/lib/threatsight/evidence-signing)",
    )
    parser.add_argument("--key-id", default=None, help="Non-secret key identifier to record beside the public key")
    args = parser.parse_args()
    directory = Path(args.dir)
    private_path = directory / "ed25519-private.pem"
    public_path = directory / "ed25519-public.pem"
    fingerprint_path = directory / "ed25519.fingerprint"
    key_id_path = directory / "ed25519.key-id"
    if private_path.exists() or public_path.exists() or fingerprint_path.exists():
        print("refusing to overwrite an existing key file", file=sys.stderr)
        return 2
    try:
        fingerprint = generate_ed25519_keypair_files(private_path=private_path, public_path=public_path)
    except PermissionError:
        print("insufficient permission to write key directory; run with the operator script", file=sys.stderr)
        return 3
    fingerprint_path.write_text(fingerprint + "\n", encoding="utf-8")
    fingerprint_path.chmod(0o444)
    key_id = args.key_id or f"local-ed25519-{uuid.uuid4().hex[:8]}"
    key_id_path.write_text(key_id + "\n", encoding="utf-8")
    key_id_path.chmod(0o444)
    print(f"key_id={key_id}")
    print(f"fingerprint={fingerprint}")
    print(f"public={public_path}")
    print(f"private={private_path} (not displayed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
