"""Add integrations table

Revision ID: 85cf2cf2b22a
Revises: 4195eeb432e9
Create Date: 2021-08-05 10:16:08.138836

"""

# revision identifiers, used by Alembic.
revision = "85cf2cf2b22a"
down_revision = "4195eeb432e9"

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import UUIDType, JSONType


def upgrade():
    op.create_table(
        "integrations",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("configuration", JSONType(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("report", sa.Boolean(), nullable=True),
        sa.Column("alert_filters", JSONType(), nullable=True),
        sa.Column("user_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "user_id", name="ix_integration_name_userid"),
    )
    op.create_index(
        op.f("ix_integrations_created_at"), "integrations", ["created_at"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_integrations_created_at"), table_name="integrations")
    op.drop_table("integrations")
