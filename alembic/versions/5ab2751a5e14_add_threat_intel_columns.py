"""Add threat intel columns

Revision ID: 5ab2751a5e14
Revises: 8e75f52597be
Create Date: 2025-08-07 11:34:35.614843

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5ab2751a5e14'
down_revision = '8e75f52597be'  # Replace with your last migration revision ID
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('lookup_data', sa.Column('threat_actor', sa.Text(), nullable=True))
    op.add_column('lookup_data', sa.Column('campaign_name', sa.Text(), nullable=True))
    op.add_column('lookup_data', sa.Column('malware_families', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('lookup_data', 'malware_families')
    op.drop_column('lookup_data', 'campaign_name')
    op.drop_column('lookup_data', 'threat_actor')
