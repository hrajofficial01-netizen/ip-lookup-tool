# alembic/env.py

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# 1) Load your .env
from dotenv import load_dotenv
load_dotenv()  # will read DB_USER, DB_PASSWORD, etc.

# 2) Pull in the same pieces that your db.py uses
DB_USER     = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = os.getenv("DB_PORT", "5432")
DB_NAME     = os.getenv("DB_NAME")

if not all([DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME]):
    raise RuntimeError("One of DB_USER/DB_PASSWORD/DB_HOST/DB_PORT/DB_NAME is missing")

# 3) Construct the URL exactly as in db.py
sqlalchemy_url = (
    f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# this is the Alembic Config object
config = context.config
# override the one in alembic.ini
config.set_main_option("sqlalchemy.url", sqlalchemy_url)

# Logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import your Base.metadata for autogenerate support
from db import Base
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, 
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
