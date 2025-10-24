"""Add apivoid_risk_score and apivoid_blacklist_detections columns to lookup_data

Revision ID: 06c85c765e08
Revises: df03ea11fc30
Create Date: 2025-10-24 16:39:55.235744

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '06c85c765e08'
down_revision: Union[str, Sequence[str], None] = 'df03ea11fc30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.add_column("lookup_data", sa.Column("apivoid_risk_score", sa.Float(), nullable=True))
    op.add_column("lookup_data", sa.Column("apivoid_blacklist_detections", sa.Integer(), nullable=True))

def downgrade():
    op.drop_column("lookup_data", "apivoid_blacklist_detections")
    op.drop_column("lookup_data", "apivoid_risk_score")
