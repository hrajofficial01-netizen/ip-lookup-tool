"""Convert hypertable to normal table

Revision ID: 67a9c44e4ed6
Revises: 4a6c2a252073
Create Date: 2025-08-24 11:02:17.279548

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '67a9c44e4ed6'
down_revision: Union[str, Sequence[str], None] = '4a6c2a252073'
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
    op.create_index('ix_search_log_normal_entry', 'search_log_normal', ['entry'])
    op.create_index('ix_search_log_normal_entry_type', 'search_log_normal', ['entry_type'])
    op.create_index('ix_search_log_normal_client_name', 'search_log_normal', ['client_name'])
    op.create_index('ix_search_log_normal_searched_at', 'search_log_normal', ['searched_at'])
    
    # 2. Copy data from hypertable (warning: large tables might be slow)
    op.execute("""
        INSERT INTO search_log_normal (id, entry_type, entry, client_name, searched_at)
        SELECT id, entry_type, entry, client_name, searched_at FROM search_log_new;
    """)
    
    # 3. You cannot run drop_hypertable here if TimescaleDB is unavailable,
    # so just drop the existing table (be cautious!)
    op.drop_table('search_log_new')
    
    # 4. Rename new table to old name
    op.rename_table('search_log_normal', 'search_log_new')

def downgrade():
    # Implement downgrade if needed
    pass
