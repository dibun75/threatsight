"""Process one durable GreyNoise lookup request in the outbound worker."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os

from sqlalchemy import text

from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.greynoise import fetch, parse


def process_pending(db, *, fetcher=fetch) -> dict:
    row = (
        db.execute(
            text(
                """
            SELECT id, ip_address FROM greynoise_lookups
            WHERE status='pending' ORDER BY requested_at
            FOR UPDATE SKIP LOCKED LIMIT 1
            """
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        return {"state": "idle"}
    db.execute(
        text(
            "UPDATE greynoise_lookups SET status='running', started_at=now() WHERE id=:id"
        ),
        {"id": row["id"]},
    )
    try:
        result = parse(
            fetcher(
                row["ip_address"],
                api_key_file=os.environ.get("THREATSIGHT_GREYNOISE_API_KEY_FILE", ""),
            ),
            row["ip_address"],
        )
    except ObservatoryError as exc:
        status = "not_found" if exc.code == "not_found" else "failed"
        db.execute(
            text(
                "UPDATE greynoise_lookups SET status=:status,error_code=:code,completed_at=now(),expires_at=:expires WHERE id=:id"
            ),
            {
                "id": row["id"],
                "status": status,
                "code": exc.code[:64],
                "expires": datetime.now(UTC)
                + timedelta(days=7 if status == "not_found" else 1),
            },
        )
        return {"state": status}
    db.execute(
        text(
            """
            UPDATE greynoise_lookups SET status='succeeded',completed_at=now(),expires_at=:expires,
              noise=:noise,riot=:riot,classification=:classification,name=:name,provider=:provider,
              reference_url=:reference_url,last_seen=:last_seen,message=:message,error_code=NULL
            WHERE id=:id
            """
        ),
        {"id": row["id"], "expires": datetime.now(UTC) + timedelta(days=7), **result},
    )
    return {"state": "succeeded"}
