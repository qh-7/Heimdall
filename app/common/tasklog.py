"""泛化的任务实时日志: stderr + 写入某个日志表。

common 不依赖任何领域模型, 因此日志表类 log_model 由调用方传入
(仿冒站传 TaskLog, 敏感监测传 MonitorLog)。
  - db 给定时复用该 Session(不关闭);
  - db 省略时自开自关一个 Session, 失败静默;
  - log_model 省略时只写 stderr, 不落库。
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

from sqlmodel import Session

from app.db import engine


def log_task(task_id: int, message: str, level: str = "info",
             db: Session | None = None, log_model=None) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] #{task_id} {message}", file=sys.stderr, flush=True)

    if log_model is None:
        return

    if db is not None:
        try:
            db.add(log_model(task_id=task_id, level=level, message=message))
            db.commit()
        except Exception as e:
            print(f"  log write error: {e}", file=sys.stderr, flush=True)
        return

    try:
        s = Session(engine)
        try:
            s.add(log_model(task_id=task_id, level=level, message=message))
            s.commit()
        finally:
            s.close()
    except Exception:
        pass
