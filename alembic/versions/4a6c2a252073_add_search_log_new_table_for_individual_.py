"""Add search_log_new table for individual search events

Revision ID: 4a6c2a252073
Revises: 5ab2751a5e14
Create Date: 2025-08-20 10:07:48.184156

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4a6c2a252073'
down_revision: Union[str, Sequence[str], None] = '5ab2751a5e14'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'search_log_new',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('entry_type', sa.String(), nullable=True),
        sa.Column('entry', sa.String, nullable=False),
        sa.Column('client_name', sa.String, nullable=False),
        sa.Column('searched_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_search_log_new_entry', 'search_log_new', ['entry'])
    op.create_index('ix_search_log_new_entry_type', 'search_log_new', ['entry_type'])
    op.create_index('ix_search_log_new_client_name', 'search_log_new', ['client_name'])
    op.create_index('ix_search_log_new_searched_at', 'search_log_new', ['searched_at'])


def downgrade():
    # Drop indexes
    op.drop_index('ix_search_log_new_entry', table_name='search_log_new')
    op.drop_index('ix_search_log_new_entry_type', table_name='search_log_new')
    op.drop_index('ix_search_log_new_client_name', table_name='search_log_new')
    op.drop_index('ix_search_log_new_searched_at', table_name='search_log_new')
    
    # Drop entry_type column
    op.drop_column('search_log_new')
