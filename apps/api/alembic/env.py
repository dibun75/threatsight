from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from threatsight_api.config import get_settings
from threatsight_api.persistence.base import Base
from threatsight_api.persistence import models as _models  # noqa: F401

config = context.config
settings = get_settings()
_PLACEHOLDER_URL = "postgresql+psycopg://threatsight:changeme-dev-only@postgres:5432/threatsight"
configured = config.get_main_option("sqlalchemy.url") or ""
if configured == _PLACEHOLDER_URL or not configured.startswith("postgresql"):
    config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
