"""Add threat actor enrichment columns

Revision ID: 707d7b3ea5eb
Revises: 5ab2751a5e14
Create Date: 2025-08-08 20:50:27.866771
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '707d7b3ea5eb'
down_revision = '5ab2751a5e14'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('lookup_data', sa.Column('country_origin', postgresql.JSONB(), nullable=True))
    op.add_column('lookup_data', sa.Column('target_sector', postgresql.JSONB(), nullable=True))
    op.add_column('lookup_data', sa.Column('threat_category', postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column('lookup_data', 'threat_category')
    op.drop_column('lookup_data', 'target_sector')
    op.drop_column('lookup_data', 'country_origin')
