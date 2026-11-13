"""Disposable PostgreSQL databases for the API suite.

Ordinary tests must never open the preserved runtime database named
``threatsight``. Callers pass a server URL only so a uniquely named database
can be created and dropped. The runtime name is refused before any statement.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url

RUNTIME_DATABASE_NAME = "threatsight"
_ISOLATED_NAME = re.compile(r"^threatsight_test_[0-9a-f]{8}$")


def isolated_database_name() -> str:
    name = f"threatsight_test_{uuid.uuid4().hex[:8]}"
    assert_isolated_name(name)
    return name


def assert_isolated_name(name: str) -> None:
    if name == RUNTIME_DATABASE_NAME or _ISOLATED_NAME.fullmatch(name) is None:
        raise RuntimeError("tests refuse the preserved runtime database")


def provision_isolated_database(runtime_url: str) -> tuple[str, str]:
    url = make_url(runtime_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("isolated tests require PostgreSQL")
    name = isolated_database_name()
    admin = url.set(database="postgres")
    engine = create_engine(admin, isolation_level="AUTOCOMMIT", pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    except Exception:
        raise RuntimeError("could not provision an isolated test database") from None
    finally:
        engine.dispose()
    return name, url.set(database=name).render_as_string(hide_password=False)


def drop_isolated_database(runtime_url: str, name: str) -> None:
    assert_isolated_name(name)
    admin = make_url(runtime_url).set(database="postgres")
    engine = create_engine(admin, isolation_level="AUTOCOMMIT", pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    finally:
        engine.dispose()
