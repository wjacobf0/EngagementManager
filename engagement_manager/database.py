"""SQLite engine and session helpers."""
from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine

from .config import get_config

_cfg = get_config()
engine = create_engine(
    _cfg.database_url,
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    SQLModel.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Add columns that `create_all` won't add to an already-existing table.

    SQLite can't drop or retype columns, but `ADD COLUMN` is safe and cheap, so
    new nullable fields are applied in place without a migration framework.
    """
    from sqlalchemy import text

    additions = {
        "scanimport": [("vantage_host_id", "INTEGER")],
    }
    with engine.begin() as conn:
        for table, cols in additions.items():
            existing = {
                row[1]
                for row in conn.execute(text(f"PRAGMA table_info({table})"))
            }
            for name, decl in cols:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {decl}"))


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
