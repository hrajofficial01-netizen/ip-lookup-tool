"""Add entry_type column to search_log

Revision ID: bf6afa4b65fb
Revises: 4a6c2a252073
Create Date: 2025-08-20 20:49:10.036851
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bf6afa4b65fb'
down_revision = '4a6c2a252073'
branch_labels = None
depends_on = None


def upgrade():
    temp_table = 'search_log_tmp'

    # 1. Create a new temporary table with desired column order and index on entry_type
    op.create_table(
        temp_table,
        sa.Column('entry', sa.String(), nullable=False),
        sa.Column('entry_type', sa.String(), nullable=True),
        sa.Column('client_name', sa.String(), nullable=False),
        sa.Column('first_searched', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_searched', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('lookup_count', sa.Integer(), nullable=False, default=1),
        sa.PrimaryKeyConstraint('entry', 'client_name', name='pk_search_log_tmp')
    )

    # Create index on entry_type
    op.create_index('ix_search_log_entry_type', temp_table, ['entry_type'])

    # 2. Copy data from old table to new temp table
    op.execute(f"""
        INSERT INTO {temp_table} (entry, entry_type, client_name, first_searched, last_searched, lookup_count)
        SELECT entry, NULL AS entry_type, client_name, first_searched, last_searched, lookup_count FROM search_log;
    """)


    # 3. Drop the old table
    op.drop_table('search_log')

    # 4. Rename temp table to original table name
    op.rename_table(temp_table, 'search_log')


def downgrade():
    temp_table = 'search_log_tmp_downgrade'

    # 1. Create original table without entry_type
    op.create_table(
        temp_table,
        sa.Column('entry', sa.String(), nullable=False),
        sa.Column('client_name', sa.String(), nullable=False),
        sa.Column('first_searched', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_searched', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('lookup_count', sa.Integer(), nullable=False, default=1),
        sa.PrimaryKeyConstraint('entry', 'client_name', name='pk_search_log')
    )

    # 2. Copy data back excluding entry_type
    op.execute(f"""
        INSERT INTO {temp_table} (entry, client_name, first_searched, last_searched, lookup_count)
        SELECT entry, client_name, first_searched, last_searched, lookup_count FROM search_log;
    """)

    # 3. Drop current table
    op.drop_table('search_log')

    # 4. Rename temp table back to original name
    op.rename_table(temp_table, 'search_log')
