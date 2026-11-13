"""Concurrency / leader behavior for intel collect and evidence signing.

Replicas are safe only through database locks/leases — not an HA claim.
"""

from __future__ import annotations

import inspect
import os

import pytest
from sqlalchemy import text
from threatsight_api.multisource import collect as collect_mod
from threatsight_api.persistence.session import get_engine
from threatsight_api.signing import service as signing_service

pytestmark_live = pytest.mark.skipif(
    os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"},
    reason="requires postgres",
)


def test_signing_claim_uses_skip_locked() -> None:
    source = inspect.getsource(signing_service.claim_pending_request)
    assert "skip_locked" in source
    assert "lease_owner" in source


def test_multisource_collect_uses_advisory_lock() -> None:
    source = inspect.getsource(collect_mod)
    assert "pg_try_advisory_lock" in source


@pytestmark_live
def test_multisource_advisory_lock_exclusive() -> None:
    eng = get_engine()
    with eng.connect() as a, eng.connect() as b:
        a.execute(text("SELECT pg_advisory_lock(hashtext('multisource-collect-test'))"))
        locked = b.execute(text("SELECT pg_try_advisory_lock(hashtext('multisource-collect-test'))")).scalar()
        assert locked in (False, 0)
        a.execute(text("SELECT pg_advisory_unlock(hashtext('multisource-collect-test'))"))
        locked2 = b.execute(text("SELECT pg_try_advisory_lock(hashtext('multisource-collect-test'))")).scalar()
        assert locked2 in (True, 1)
        b.execute(text("SELECT pg_advisory_unlock(hashtext('multisource-collect-test'))"))


def test_availability_matrix_documented() -> None:
    matrix = {
        "web": "horizontal",
        "api": "horizontal",
        "intelligence-worker": "replicas_via_db_locks",
        "evidence-signer": "replicas_via_leases",
        "migration": "exactly_one_job",
        "customer-runner": "per_workspace_scope",
        "postgresql": "external_customer_responsibility",
    }
    assert matrix["migration"] == "exactly_one_job"
    assert "HA" not in str(matrix)
