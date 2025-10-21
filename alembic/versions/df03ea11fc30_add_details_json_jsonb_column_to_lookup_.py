"""Add details_json JSONB column to lookup_data

Revision ID: df03ea11fc30
Revises: 2fd7e242576b
Create Date: 2025-10-21 21:57:08.280848

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'df03ea11fc30'
down_revision: Union[str, Sequence[str], None] = '2fd7e242576b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Add nullable JSONB column for enriched IOC fields
    op.add_column('lookup_data',
        sa.Column('details_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    # Create a GIN index on details_json for faster querying on json fields
    op.create_index('ix_lookup_data_details_json', 'lookup_data', ['details_json'], postgresql_using='gin')


def downgrade():
    # Remove index and column on downgrade
    op.drop_index('ix_lookup_data_details_json', table_name='lookup_data')
    op.drop_column('lookup_data', 'details_json')