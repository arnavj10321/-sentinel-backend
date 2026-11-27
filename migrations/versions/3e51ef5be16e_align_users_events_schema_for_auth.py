"""align users events schema for auth

Revision ID: 3e51ef5be16e
Revises: e70910724ff7
Create Date: 2026-11-24 17:32:25.072700

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3e51ef5be16e"
down_revision: str | Sequence[str] | None = "e70910724ff7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "events", sa.Column("event_type", sa.String(length=100), nullable=True)
    )
    op.add_column(
        "events", sa.Column("ip_address", sa.String(length=64), nullable=True)
    )
    op.add_column("events", sa.Column("payload", sa.Text(), nullable=True))
    op.execute("UPDATE events SET event_type = type WHERE event_type IS NULL")
    op.execute("UPDATE events SET source = 'unknown' WHERE source IS NULL")
    op.alter_column(
        "events", "event_type", existing_type=sa.String(length=100), nullable=False
    )
    op.alter_column(
        "events", "source", existing_type=sa.VARCHAR(length=255), nullable=False
    )
    op.drop_index(op.f("ix_events_type"), table_name="events")
    op.create_index(
        op.f("ix_events_event_type"), "events", ["event_type"], unique=False
    )
    op.drop_column("events", "message")
    op.drop_column("events", "type")

    op.add_column("users", sa.Column("role", sa.String(length=50), nullable=True))
    op.execute("UPDATE users SET role = 'user' WHERE role IS NULL")
    op.alter_column("users", "role", existing_type=sa.String(length=50), nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column("users", "role", existing_type=sa.String(length=50), nullable=True)
    op.drop_column("users", "role")

    op.add_column(
        "events",
        sa.Column("type", sa.VARCHAR(length=100), autoincrement=False, nullable=True),
    )
    op.add_column(
        "events", sa.Column("message", sa.TEXT(), autoincrement=False, nullable=True)
    )
    op.execute("UPDATE events SET type = event_type WHERE type IS NULL")
    op.alter_column(
        "events", "type", existing_type=sa.VARCHAR(length=100), nullable=False
    )
    op.drop_index(op.f("ix_events_event_type"), table_name="events")
    op.create_index(op.f("ix_events_type"), "events", ["type"], unique=False)
    op.alter_column(
        "events", "source", existing_type=sa.VARCHAR(length=255), nullable=True
    )
    op.drop_column("events", "payload")
    op.drop_column("events", "ip_address")
    op.drop_column("events", "event_type")
