from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from threatsight_api.config import Settings


def _alembic_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2],
        here.parents[1],
        Path.cwd(),
        Path("/app"),
    ]
    for path in candidates:
        if (path / "alembic.ini").is_file() and (path / "alembic").is_dir():
            return path
    raise FileNotFoundError("alembic.ini not found next to the alembic/ directory")


def create_engine_from_settings(settings: Settings):
    return create_engine(settings.database_url, pool_pre_ping=True)


def run_migrations(settings: Settings) -> None:
    root = _alembic_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


def check_database(settings: Settings) -> None:
    engine = create_engine_from_settings(settings)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
