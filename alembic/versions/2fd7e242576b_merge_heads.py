"""merge heads


Revision ID: 2fd7e242576b
Revises: 67a9c44e4ed6, bf6afa4b65fb
Create Date: 2025-08-24 11:08:26.594682

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '2fd7e242576b'
down_revision: Union[str, Sequence[str], None] = ('67a9c44e4ed6', 'bf6afa4b65fb')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # 1. Create normal table
    op.create_table(
        'search_log_normal',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('entry_type', sa.String(), nullable=True),
        sa.Column('entry', sa.String, nullable=False),
        sa.Column('client_name', sa.String, nullable=False),
        sa.Column('searched_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    # 2. Create indexes only if they do not exist
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'ix_search_log_normal_entry'
              AND n.nspname = 'public'
        ) THEN
            CREATE INDEX ix_search_log_normal_entry ON public.search_log_normal (entry);
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'ix_search_log_normal_entry_type'
              AND n.nspname = 'public'
        ) THEN
            CREATE INDEX ix_search_log_normal_entry_type ON public.search_log_normal (entry_type);
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'ix_search_log_normal_client_name'
              AND n.nspname = 'public'
        ) THEN
            CREATE INDEX ix_search_log_normal_client_name ON public.search_log_normal (client_name);
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'ix_search_log_normal_searched_at'
              AND n.nspname = 'public'
        ) THEN
            CREATE INDEX ix_search_log_normal_searched_at ON public.search_log_normal (searched_at);
        END IF;
    END
    $$;
    """)

    # 3. Copy data from hypertable (warning: large tables might be slow)
    op.execute("""
        INSERT INTO search_log_normal (id, entry_type, entry, client_name, searched_at)
        SELECT id, entry_type, entry, client_name, searched_at FROM search_log_new;
    """)

    # 4. Drop old hypertable and rename new normal table
    op.drop_table('search_log_new')
    op.rename_table('search_log_normal', 'search_log_new')


def downgrade():
    # Implement downgrade if needed
    pass
