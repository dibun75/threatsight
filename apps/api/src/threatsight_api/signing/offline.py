"""Offline verification of portable evidence bundles. No database or network."""

from __future__ import annotations

import base64
import json
from typing import Any

from threatsight_api.signing import ALGORITHMS, SIGNATURE_SCHEMA
from threatsight_api.signing.envelope import canonical_json, digest_bytes
from threatsight_api.signing.provider import verify_ed25519


def verify_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    try:
        manifest = bundle["manifest"]
        signature = bundle["signature"]
        public_key = bundle["public_key"]
        canonical_manifest = manifest["canonical_json"]
        digest = manifest["digest"]
        envelope = signature["canonical_envelope"]
        signature_b64 = signature["signature_b64"]
        algorithm = signature["algorithm"]
        key_pem = public_key["public_key_pem"]
        key_status = public_key.get("status", "active")
        action_status = (bundle.get("verification") or {}).get("action_status") or bundle.get("action_status")
    except (KeyError, TypeError):
        return {"state": "malformed_bundle", "valid": False, "human": "Bundle is missing required fields."}

    if algorithm not in ALGORITHMS:
        return {"state": "unsupported_algorithm", "valid": False, "human": f"Unsupported algorithm {algorithm}."}

    try:
        recomputed = digest_bytes(canonical_json(json.loads(canonical_manifest)))
    except Exception:
        return {"state": "malformed_bundle", "valid": False, "human": "Manifest JSON is malformed."}
    if recomputed != digest:
        return {"state": "invalid_manifest_digest", "valid": False, "human": "Manifest digest does not match canonical content."}

    try:
        envelope_obj = json.loads(envelope)
    except Exception:
        return {"state": "malformed_bundle", "valid": False, "human": "Signature envelope is malformed."}
    if envelope_obj.get("schema_version") != SIGNATURE_SCHEMA:
        return {"state": "malformed_bundle", "valid": False, "human": "Unsupported signature envelope version."}
    if envelope_obj.get("manifest_digest") != digest:
        return {"state": "invalid_manifest_digest", "valid": False, "human": "Envelope digest does not match manifest."}
    if digest_bytes(canonical_json(envelope_obj)) != digest_bytes(envelope if envelope == canonical_json(envelope_obj) else canonical_json(envelope_obj)):
        # Ensure envelope is canonical when re-serialized
        if canonical_json(envelope_obj) != envelope:
            return {"state": "invalid_signature", "valid": False, "human": "Envelope is not in canonical form."}

    try:
        sig = base64.b64decode(signature_b64)
    except Exception:
        return {"state": "invalid_signature", "valid": False, "human": "Signature encoding is invalid."}

    if not verify_ed25519(public_key_pem=key_pem, message=envelope.encode(), signature=sig):
        return {"state": "invalid_signature", "valid": False, "human": "Cryptographic signature verification failed."}

    if key_status == "revoked":
        state = "valid_key_revoked_after_signing"
        human = "Signature is cryptographically valid, but the key was revoked after signing."
    elif key_status == "retired":
        state = "valid_key_retired"
        human = "Signature is cryptographically valid under a retired key."
    elif action_status and action_status != "closed":
        state = "valid_superseded"
        human = "Valid signature for a superseded closure."
    else:
        state = "valid_current"
        human = "Valid current deployment signature for the finalized manifest digest."

    return {
        "state": state,
        "valid": state.startswith("valid_"),
        "human": human,
        "manifest_digest": digest,
        "fingerprint": public_key.get("fingerprint"),
        "key_id": public_key.get("key_id"),
        "signed_at": signature.get("signed_at"),
        "does_not_prove": "Evidence factual correctness, control effectiveness, compliance, or auditor approval.",
    }


def verify_bundle_file(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        bundle = json.load(handle)
    if "bundle" in bundle and isinstance(bundle["bundle"], dict):
        bundle = bundle["bundle"]
    return verify_bundle(bundle)
