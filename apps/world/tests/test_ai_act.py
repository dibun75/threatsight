import json
import threading
import urllib.request
from pathlib import Path

import pytest

from threatsight_world.ai_act import ai_act_evidence
from threatsight_world.server import Config, serve


def run(verdicts, reasons=None, records=5):
    reasons = reasons or ["X"] * len(verdicts)
    return {"runs": [{"verdict": {"verdict": v, "reason_code": c}} for v, c in zip(verdicts, reasons)],
            "evidence": {"records": records, "signed": True}}


def by(out):
    return {i["article"]: i for i in out["items"]}


def test_stopped_attack_supports_article_15_and_never_claims_compliance():
    out = ai_act_evidence(run(["FAIL", "PASS"]))
    a = by(out)
    assert a["Article 15(5)"]["strength"] == "supports"
    assert {"Article 9", "Article 12"} <= set(a)
    assert "not a statement that the system complies" in out["disclaimer"]
    assert "complian" not in " ".join(i["evidence"] for i in out["items"]).lower()


def test_harm_is_a_gap_and_untried_attack_is_no_evidence():
    assert by(ai_act_evidence(run(["FAIL"])))["Article 15(5)"]["strength"] == "gap"
    assert by(ai_act_evidence(run(["INCONCLUSIVE"])))["Article 15(5)"]["strength"] == "none"


def test_article_14_only_when_a_call_was_held():
    assert "Article 14" not in by(ai_act_evidence(run(["PASS"])))
    assert "Article 14" in by(ai_act_evidence(run(["PASS"], ["HELD_FOR_APPROVAL"])))


def test_run_endpoint_includes_ai_act(tmp_path: Path):
    httpd = serve(Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}/api/world"
    try:
        req = urllib.request.Request(f"{base}/runs", data=json.dumps({"scenario": "payment-injection", "model": "scripted", "mode": "retest"}).encode(),
                                     headers={"Content-Type": "application/json"})
        rid = json.loads(urllib.request.urlopen(req, timeout=30).read())["id"]
        got = json.loads(urllib.request.urlopen(f"{base}/runs/{rid}", timeout=30).read())
    finally:
        httpd.shutdown()
    assert by(got["ai_act"])["Article 15(5)"]["strength"] == "supports"
