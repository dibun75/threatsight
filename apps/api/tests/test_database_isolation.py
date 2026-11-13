from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url

from threatsight_api.config import get_settings
from threatsight_api.test_database import assert_isolated_name, isolated_database_name

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}


def test_runtime_database_name_is_refused() -> None:
    with pytest.raises(RuntimeError, match="preserved runtime database"):
        assert_isolated_name("threatsight")


def test_isolated_names_are_disposable() -> None:
    first = isolated_database_name()
    second = isolated_database_name()
    assert first != second
    assert first.startswith("threatsight_test_")
    assert_isolated_name(first)
    with pytest.raises(RuntimeError):
        assert_isolated_name("threatsight_test_not-hex")
    with pytest.raises(RuntimeError):
        assert_isolated_name("threatsight_test_")


@pytest.mark.skipif(not LIVE, reason="requires postgres")
def test_api_suite_is_not_connected_to_the_runtime_database() -> None:
    name = make_url(get_settings().database_url).database
    assert name is not None
    assert_isolated_name(name)
    engine = create_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            current = connection.execute(text("SELECT current_database()")).scalar_one()
        assert current == name
        assert current != "threatsight"
    finally:
        engine.dispose()
