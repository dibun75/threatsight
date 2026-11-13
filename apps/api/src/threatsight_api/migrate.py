from __future__ import annotations

from threatsight_api.config import get_settings
from threatsight_api.db import check_database, run_migrations
from threatsight_api.logging import configure_logging


def main() -> None:
    settings = get_settings()
    configure_logging(json_logs=settings.log_json, level=settings.log_level)
    run_migrations(settings)
    check_database(settings)
    print("ThreatSight database migration complete.")


if __name__ == "__main__":
    main()
