"""
Offline Air-Gapped `.lexpack.zip` Evidence Bundle Verifier CLI.

Usage:
  python -m lexgraph_lah.attestation.verify_cli --bundle path/to/evidence.lexpack.zip [--pubkey pub.pem]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lexgraph_lah.attestation.bundle import verify_lexpack_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline zero-network cryptographic verifier for .lexpack.zip evidence bundles."
    )
    parser.add_argument(
        "--bundle",
        required=True,
        type=Path,
        help="Path to the .lexpack.zip evidence bundle.",
    )
    parser.add_argument(
        "--pubkey",
        required=False,
        type=Path,
        default=None,
        help="Optional trusted Ed25519 public key PEM file to verify against.",
    )
    args = parser.parse_args(argv)

    pub_pem: str | None = None
    if args.pubkey is not None:
        if not args.pubkey.is_file():
            out = {
                "verified": False,
                "status": "ERROR",
                "manifest_id": None,
                "reasons": [f"Public key file not found: {args.pubkey}"],
            }
            print(json.dumps(out, indent=2))
            return 1
        pub_pem = args.pubkey.read_text(encoding="utf-8")

    result = verify_lexpack_bundle(args.bundle, pubkey_pem=pub_pem)
    print(json.dumps(result, indent=2))
    return 0 if result.get("verified") is True else 1


if __name__ == "__main__":
    sys.exit(main())
