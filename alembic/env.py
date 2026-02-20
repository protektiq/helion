"""Alembic environment: uses app config for DATABASE_URL and Base.metadata for autogenerate."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

# Import app config and models so target_metadata is set and we use the same DB URL.
os.environ.setdefault("APP_ENV", "dev")
from app.core.config import settings
from app.models import Base

# Import all models so that Base.metadata contains every table.
from app.models import Finding, User  # noqa: F401

config = context.config
# Load logging from alembic.ini only if it defines [formatters], [handlers], [loggers].
# Skip when those sections are missing (fileConfig would raise KeyError).
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except KeyError:
        pass

target_metadata = Base.metadata


def get_url() -> str:
    """Return the database URL from application settings."""
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generate SQL only)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB and run)."""
    connectable = create_engine(get_url(), poolclass=NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
