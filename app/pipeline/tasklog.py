"""仿冒站发现的任务日志: 转发到 app.common.tasklog, 固定写入 TaskLog 表。

保留本模块名与 log_task 签名不变, 现有调用点(orchestrator/behavior/discovery)零改动。
真正的实现在 app.common.tasklog。
"""
from __future__ import annotations

from sqlmodel import Session

from app.common.tasklog import log_task as _log_task
from app.models import TaskLog


def log_task(task_id: int, message: str, level: str = "info",
             db: Session | None = None) -> None:
    _log_task(task_id, message, level, db=db, log_model=TaskLog)
