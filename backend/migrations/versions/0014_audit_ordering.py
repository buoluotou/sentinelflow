"""audit ordering: PostgreSQL created_at default -> clock_timestamp()

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-10

RC2 / H-2 — eliminate the process-global audit clock. Pre-RC2 the
``execution_log.created_at`` value was stamped in Python through a
process-global high-water mark (``_LAST_AUDIT_STAMP``): not thread-safe (a
read-modify-write race could hand two rows the same stamp) and per-process
only, so multi-worker correctness was an illusion. RC2 removes that state:
``created_at`` comes from the DATABASE at INSERT, and the sanctioned
``(created_at, id)`` tie-break is made deterministic by minting ``id`` from
the insert-ordered uuid7 generator (``app.core.ids``).

This migration is PostgreSQL-only and touches NO data:
- PostgreSQL: ``created_at`` default becomes ``clock_timestamp()`` — the
  statement's real wall clock (microsecond), NEVER the transaction-start
  ``now()``, which would give every row of one chain the same timestamp.
- SQLite: no change — ``CURRENT_TIMESTAMP`` (second precision) stays; its
  same-second ties are exactly what the uuid7 id tie-break resolves.

No column is added/changed/dropped; historical rows keep their facts.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ALTER ... SET DEFAULT needs no table rewrite and no row change.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE execution_log "
            "ALTER COLUMN created_at SET DEFAULT clock_timestamp()"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE execution_log "
            "ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP"
        )
