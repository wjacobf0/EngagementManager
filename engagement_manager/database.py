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


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
