"""Tamper-evident evidence log.

Each record contains the SHA-256 of the previous record, so editing or removing any record breaks
every record after it. With THREATSIGHT_EVIDENCE_KEY set, each record is also HMAC-signed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

GENESIS = "0" * 64


def _canon(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(index: int, ts: str, kind: str, payload: Any, prev: str) -> str:
    return hashlib.sha256(f"{index}|{ts}|{kind}|{_canon(payload)}|{prev}".encode()).hexdigest()


def _sign(key: str | None, digest: str) -> str | None:
    return hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest() if key else None


class EvidenceLog:
    def __init__(self, key: str | None = None, clock: Callable[[], str] | None = None, parent_hash: str | None = None) -> None:
        self.key = key if key is not None else os.environ.get("THREATSIGHT_EVIDENCE_KEY")
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self.records: list[dict[str, Any]] = []
        self.parent_hash = parent_hash

    @property
    def last_hash(self) -> str:
        return self.records[-1]["hash"] if self.records else (self.parent_hash or GENESIS)

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        index = len(self.records)
        ts = self._clock()
        prev = self.last_hash
        digest = _hash(index, ts, kind, payload, prev)
        rec = {"index": index, "ts": ts, "kind": kind, "payload": payload, "prev_hash": prev, "hash": digest, "sig": _sign(self.key, digest)}
        self.records.append(rec)
        return rec

    def verify(self) -> tuple[bool, int | None, str]:
        return verify_records(self.records, self.key, self.parent_hash)

    def write(self, path: str | Path) -> None:
        Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in self.records))


def verify_records(records: list[dict[str, Any]], key: str | None = None, parent_hash: str | None = None) -> tuple[bool, int | None, str]:
    prev = parent_hash or (records[0]["prev_hash"] if records else GENESIS)
    for i, r in enumerate(records):
        if r["index"] != i:
            return False, i, f"record {i}: index out of order"
        if r["prev_hash"] != prev:
            return False, i, f"record {i}: does not follow the previous record"
        if _hash(i, r["ts"], r["kind"], r["payload"], prev) != r["hash"]:
            return False, i, f"record {i}: content does not match its hash"
        if key and r.get("sig") != _sign(key, r["hash"]):
            return False, i, f"record {i}: signature mismatch"
        prev = r["hash"]
    return True, None, f"chain intact: {len(records)} records"


def load(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
