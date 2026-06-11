"""SQLite 引擎与建表。"""
from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from app.config import get_config

_cfg = get_config()
_db_path: Path = _cfg.abspath(_cfg.get("general.db_path", "app/data/app.db"))
_db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{_db_path}",
    connect_args={"check_same_thread": False},
)

# 启用 WAL 模式 + busy timeout, 避免 "database is locked"
from sqlalchemy import event
@event.listens_for(engine, "connect")
def _set_pragma(dbapi_conn, _):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def init_db() -> None:
    # 确保两个领域的模型都已被导入再建表(Mount 不转发 lifespan, 统一在主 app 建表)
    from app import models  # noqa: F401
    from app.sensitive import models as sensitive_models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)
