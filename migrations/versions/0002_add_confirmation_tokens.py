"""Add server-side single-use confirmation tokens (M5)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_confirm_tokens"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "confirmation_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_confirmation_tokens_user_id"), "confirmation_tokens", ["user_id"])
    op.create_index(
        op.f("ix_confirmation_tokens_token"), "confirmation_tokens", ["token"], unique=True
    )
    op.create_index(op.f("ix_confirmation_tokens_action"), "confirmation_tokens", ["action"])
    op.create_index(
        op.f("ix_confirmation_tokens_consumed_at"), "confirmation_tokens", ["consumed_at"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_confirmation_tokens_consumed_at"), table_name="confirmation_tokens")
    op.drop_index(op.f("ix_confirmation_tokens_action"), table_name="confirmation_tokens")
    op.drop_index(op.f("ix_confirmation_tokens_token"), table_name="confirmation_tokens")
    op.drop_index(op.f("ix_confirmation_tokens_user_id"), table_name="confirmation_tokens")
    op.drop_table("confirmation_tokens")
