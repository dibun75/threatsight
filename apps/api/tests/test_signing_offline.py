"""Offline verifier and envelope canonicalization — no database or network."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from threatsight_api.signing.envelope import build_envelope, canonical_json, digest_bytes
from threatsight_api.signing.offline import verify_bundle
from threatsight_api.signing.provider import FileEd25519Provider, generate_ed25519_keypair_files, verify_ed25519


def test_canonical_digest_is_deterministic_and_sensitive() -> None:
    body = {"b": 1, "a": "x"}
    first = digest_bytes(canonical_json(body))
    second = digest_bytes(canonical_json({"a": "x", "b": 1}))
    assert first == second
    assert digest_bytes(canonical_json({"a": "y", "b": 1})) != first


def test_ed25519_sign_verify_and_offline_bundle(tmp_path: Path) -> None:
    private = tmp_path / "ed25519-private.pem"
    public = tmp_path / "ed25519-public.pem"
    fingerprint = generate_ed25519_keypair_files(private_path=private, public_path=public)
    provider = FileEd25519Provider(key_path=private, key_id="test-key-1")
    material = provider.public_material()
    assert material.fingerprint == fingerprint
    manifest_body = {"schema_version": "threatsight.manifest.v1", "action_id": "a", "digest_field": "v"}
    manifest_canonical = canonical_json(manifest_body)
    manifest_digest = digest_bytes(manifest_canonical)
    _envelope, envelope_canonical, _ = build_envelope(
        manifest_schema_version="threatsight.manifest.v1",
        manifest_id="11111111-1111-1111-1111-111111111111",
        manifest_digest=manifest_digest,
        tenant_id="22222222-2222-2222-2222-222222222222",
        workspace_id="33333333-3333-3333-3333-333333333333",
        action_id="44444444-4444-4444-4444-444444444444",
        closure_outcome="resolved_by_evidence",
        reviewer_subject="ready-reviewer-ordering",
        signing_key_id=material.key_id,
        algorithm="Ed25519",
        deployment_id="threatsight-local",
        signed_at=datetime(2026, 11, 3, 12, 0, tzinfo=UTC),
        previous_signature_id=None,
    )
    signature = provider.sign(envelope_canonical.encode())
    assert verify_ed25519(public_key_pem=material.public_key_pem, message=envelope_canonical.encode(), signature=signature)
    bundle = {
        "manifest": {"id": "m", "schema_version": "threatsight.manifest.v1", "digest": manifest_digest, "canonical_json": manifest_canonical},
        "signature": {
            "id": "s",
            "envelope_version": "threatsight.signature.v1",
            "canonical_envelope": envelope_canonical,
            "signature_b64": base64.b64encode(signature).decode(),
            "algorithm": "Ed25519",
            "signing_key_id": material.key_id,
            "deployment_id": "threatsight-local",
            "signed_at": "2026-11-03T12:00:00Z",
            "label": "Reference-signed evidence",
        },
        "public_key": {
            "key_id": material.key_id,
            "fingerprint": material.fingerprint,
            "algorithm": "Ed25519",
            "public_key_pem": material.public_key_pem,
            "status": "active",
            "provider_type": "file_ed25519",
        },
        "action_status": "closed",
    }
    ok = verify_bundle(bundle)
    assert ok["state"] == "valid_current"
    assert ok["valid"] is True
    bad = json.loads(json.dumps(bundle))
    bad["manifest"]["digest"] = "0" * 64
    assert verify_bundle(bad)["state"] == "invalid_manifest_digest"
    flipped = json.loads(json.dumps(bundle))
    flipped["signature"]["signature_b64"] = base64.b64encode(b"\x00" * 64).decode()
    assert verify_bundle(flipped)["state"] == "invalid_signature"
    superseded = json.loads(json.dumps(bundle))
    superseded["action_status"] = "reopened"
    assert verify_bundle(superseded)["state"] == "valid_superseded"
    revoked = json.loads(json.dumps(bundle))
    revoked["public_key"]["status"] = "revoked"
    assert verify_bundle(revoked)["state"] == "valid_key_revoked_after_signing"


def test_generate_refuses_overwrite(tmp_path: Path) -> None:
    private = tmp_path / "ed25519-private.pem"
    public = tmp_path / "ed25519-public.pem"
    generate_ed25519_keypair_files(private_path=private, public_path=public)
    try:
        generate_ed25519_keypair_files(private_path=private, public_path=public)
        assert False, "expected FileExistsError"
    except FileExistsError:
        pass
