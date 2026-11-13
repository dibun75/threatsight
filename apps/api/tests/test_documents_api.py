from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app
from test_document_intelligence import INJECTION, POLICY, make_docx, make_pdf

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _upload(client: TestClient, filename: str, content: bytes, title: str | None = None, content_type: str = "text/plain"):
    data = {"title": title} if title else None
    return client.post(
        "/api/v1/documents",
        headers={"X-Actor": "reviewer.alex"},
        files={"file": (filename, content, content_type)},
        data=data,
    )


def test_document_intelligence_exit_criteria(client: TestClient) -> None:
    first = _upload(client, "ai-policy.md", POLICY.encode(), title="Internal AI policy", content_type="text/markdown")
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["status"] == "ready"
    assert body["current_version"] == 1
    assert body["latest_hash"]
    document_id = body["id"]
    version_id = body["versions"][0]["id"]
    assert body["versions"][0]["content_hash"] == body["latest_hash"]
    assert any(item["candidate_type"] == "requirement" for item in body["candidates"])

    listed = client.get("/api/v1/documents", params={"limit": 100})
    assert listed.status_code == 200
    found = any(item["id"] == document_id for item in listed.json())
    offset = 100
    while not found and offset <= 1000:
        page = client.get("/api/v1/documents", params={"limit": 100, "offset": offset})
        assert page.status_code == 200
        rows = page.json()
        found = any(item["id"] == document_id for item in rows)
        if len(rows) < 100:
            break
        offset += 100
    assert found

    detail = client.get(f"/api/v1/documents/{document_id}")
    assert detail.status_code == 200
    requirement = next(item for item in detail.json()["candidates"] if item["candidate_type"] == "requirement")
    assert requirement["review_status"] == "pending"
    assert requirement["provenance"]["content_hash"] == body["latest_hash"]
    assert requirement["provenance"]["quote"]
    assert requirement["provenance"]["extraction_method"] == "heuristic"
    candidate_id = requirement["id"]

    citation = client.get(f"/api/v1/candidates/{candidate_id}/citation")
    assert citation.status_code == 200
    assert citation.json()["provenance"]["document_id"] == document_id

    edited = client.patch(
        f"/api/v1/candidates/{candidate_id}",
        headers={"X-Actor": "reviewer.alex"},
        json={"title": "Gateway tool authorization"},
    )
    assert edited.status_code == 200
    assert edited.json()["title"] == "Gateway tool authorization"

    approved = client.post(
        f"/api/v1/candidates/{candidate_id}/review",
        headers={"X-Actor": "reviewer.alex"},
        json={"decision": "approved", "comment": "Accepted as a governance requirement."},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["review_status"] == "approved"
    requirement_id = approved.json()["authoritative_requirement_id"]
    assert requirement_id
    stored = client.get(f"/api/v1/requirements/{requirement_id}")
    assert stored.status_code == 200
    assert stored.json()["status"] == "approved"
    assert stored.json()["source_type"] == "document"

    control = client.post(
        "/api/v1/controls",
        headers={"X-Actor": "reviewer.alex"},
        json={
            "identifier": f"CTRL-{uuid.uuid4().hex[:8].upper()}",
            "title": "External tool authorization",
            "objective": "Deny unauthorized high-impact tools.",
            "owner": "security",
        },
    )
    assert control.status_code == 201
    control_id = control.json()["id"]
    mapped = client.post(
        f"/api/v1/candidates/{candidate_id}/map-control",
        headers={"X-Actor": "reviewer.alex"},
        json={
            "action": "link_existing",
            "control_id": control_id,
            "rationale": "This control tests the extracted requirement.",
        },
    )
    assert mapped.status_code == 201, mapped.text
    assert mapped.json()["control_id"] == control_id
    assert mapped.json()["reviewer"] == "reviewer.alex"
    assert "document:" in mapped.json()["provenance"]

    rejected_other = next(item for item in detail.json()["candidates"] if item["id"] != candidate_id)
    rejected = client.post(
        f"/api/v1/candidates/{rejected_other['id']}/review",
        headers={"X-Actor": "reviewer.alex"},
        json={"decision": "rejected", "comment": "Out of scope."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["review_status"] == "rejected"
    assert rejected.json()["authoritative_requirement_id"] is None

    v2_text = POLICY + "\nThe organization shall record human review of extracted requirements.\n"
    second = client.post(
        f"/api/v1/documents/{document_id}/versions",
        headers={"X-Actor": "reviewer.alex"},
        files={"file": ("ai-policy-v2.md", v2_text.encode(), "text/markdown")},
    )
    assert second.status_code == 201, second.text
    assert second.json()["current_version"] == 2
    hashes = {item["content_hash"] for item in second.json()["versions"]}
    assert len(hashes) == 2
    v2_candidates = [item for item in second.json()["candidates"] if item["version_number"] == 2]
    assert v2_candidates
    v1_still = [item for item in second.json()["candidates"] if item["document_version_id"] == version_id]
    assert v1_still
    assert any(item["id"] == candidate_id and item["review_status"] == "approved" for item in v1_still)

    duplicate = client.post(
        f"/api/v1/documents/{document_id}/versions",
        headers={"X-Actor": "reviewer.alex"},
        files={"file": ("ai-policy-v2.md", v2_text.encode(), "text/markdown")},
    )
    assert duplicate.status_code == 409

    audit = client.get("/api/v1/audit", params={"entity_type": "document", "entity_id": document_id})
    assert audit.status_code == 200
    actions = {item["action"] for item in audit.json()}
    assert "create" in actions
    assert "version" in actions
    assert "extract" in actions
    assert "review" in actions
    assert "map" in actions

    version_detail = client.get(f"/api/v1/documents/{document_id}/versions/{version_id}")
    assert version_detail.status_code == 200
    assert "shall enforce tool authorization" in version_detail.json()["extracted_text"]


def test_pdf_and_docx_ingestion(client: TestClient) -> None:
    pdf = _upload(
        client,
        "policy.pdf",
        make_pdf(["The organization shall enforce tool authorization outside the model."]),
        title="PDF policy",
        content_type="application/pdf",
    )
    assert pdf.status_code == 201, pdf.text
    assert pdf.json()["latest_media_kind"] == "pdf"
    assert pdf.json()["versions"][0]["page_count"] == 1
    requirement = next(item for item in pdf.json()["candidates"] if item["candidate_type"] == "requirement")
    assert requirement["provenance"]["page"] == 1

    docx = _upload(client, "policy.docx", make_docx(POLICY), title="DOCX policy")
    assert docx.status_code == 201, docx.text
    assert docx.json()["latest_media_kind"] == "docx"
    assert any(item["candidate_type"] == "requirement" for item in docx.json()["candidates"])


def test_malformed_and_oversized_documents(client: TestClient) -> None:
    bad_pdf = _upload(client, "bad.pdf", b"%PDF-1.4 nope")
    assert bad_pdf.status_code == 400
    bad_docx = _upload(client, "bad.docx", b"PK\x03\x04nope")
    assert bad_docx.status_code == 400
    empty = _upload(client, "empty.txt", b"")
    assert empty.status_code == 400
    exe = _upload(client, "payload.exe", b"MZ\x00\x00not-a-document")
    assert exe.status_code == 400
    too_big = _upload(client, "huge.txt", b"x" * (10_485_760 + 1))
    assert too_big.status_code == 413


def test_prompt_injection_document_cannot_approve_or_claim_compliance(client: TestClient) -> None:
    mixed = (INJECTION + "\nThe organization shall keep a human in the loop for extracted requirements.\n").encode()
    uploaded = _upload(client, "injection.md", mixed, title="Untrusted memo")
    assert uploaded.status_code == 201, uploaded.text
    body = uploaded.json()
    assert body["status"] == "ready"
    for candidate in body["candidates"]:
        assert candidate["review_status"] == "pending"
        assert candidate.get("assurance_status") is None
        assert "COMPLIANT" not in candidate["title"]
    requirements = client.get("/api/v1/requirements").json()
    from_this = [item for item in requirements if item.get("source_reference") and body["id"] in item["source_reference"]]
    assert from_this == []
    forbidden = client.post(
        "/api/v1/controls",
        json={
            "identifier": f"CTRL-{uuid.uuid4().hex[:8].upper()}",
            "title": "Injection must not authorize status",
            "objective": "Keep extraction untrusted.",
            "owner": "security",
            "assurance_status": "COMPLIANT",
        },
    )
    assert forbidden.status_code == 422


def test_propose_new_control_from_approved_requirement(client: TestClient) -> None:
    uploaded = _upload(client, "map.md", POLICY.encode(), title="Mapping policy")
    candidate = next(item for item in uploaded.json()["candidates"] if item["candidate_type"] == "requirement")
    approved = client.post(
        f"/api/v1/candidates/{candidate['id']}/review",
        headers={"X-Actor": "reviewer.alex"},
        json={"decision": "approved"},
    )
    assert approved.status_code == 200
    ident = f"DOC-{uuid.uuid4().hex[:8].upper()}"
    mapped = client.post(
        f"/api/v1/candidates/{candidate['id']}/map-control",
        headers={"X-Actor": "reviewer.alex"},
        json={
            "action": "propose_new",
            "new_control": {
                "identifier": ident,
                "title": "Proposed gateway authorization",
                "objective": "Deny unauthorized tools at the gateway.",
                "owner": "security",
                "severity": "high",
            },
            "rationale": "New control candidate from the document.",
        },
    )
    assert mapped.status_code == 201, mapped.text
    created = client.get(f"/api/v1/controls/{mapped.json()['control_id']}")
    assert created.status_code == 200
    assert created.json()["identifier"] == ident
    assert created.json()["assurance_status"] == "HUMAN_REVIEW_REQUIRED"
    pending_map = client.post(
        f"/api/v1/candidates/{candidate['id']}/map-control",
        json={"action": "reject", "rationale": "second thought"},
    )
    assert pending_map.status_code == 201
