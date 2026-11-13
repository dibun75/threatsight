#!/usr/bin/env python3
"""Offline verifier for ThreatSight evidence verification bundles.

No database, private key, credentials, or network access required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/api/src"))

from threatsight_api.signing.offline import verify_bundle_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="Path to verification bundle JSON")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON only")
    args = parser.parse_args()
    result = verify_bundle_file(args.bundle)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"state={result['state']}")
        print(f"valid={result['valid']}")
        print(result.get("human", ""))
        if result.get("manifest_digest"):
            print(f"manifest_digest={result['manifest_digest']}")
        if result.get("fingerprint"):
            print(f"fingerprint={result['fingerprint']}")
        if result.get("does_not_prove"):
            print(f"does_not_prove={result['does_not_prove']}")
    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
