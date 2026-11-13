from collections.abc import Generator

from sqlalchemy.orm import Session, sessionmaker

from threatsight_api.config import base_settings
from threatsight_api.db import create_engine_from_settings

_engine = None
SessionLocal = sessionmaker(autoflush=False, autocommit=False, expire_on_commit=False)


def configure_engine() -> None:
    global _engine
    _engine = create_engine_from_settings(base_settings())
    SessionLocal.configure(bind=_engine)


def get_engine():
    if _engine is None:
        configure_engine()
    return _engine


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
