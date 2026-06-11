"""敏感信息监测子应用: API 路由 + 静态前端。

作为独立 FastAPI 实例, 由 app/main.py 通过 app.mount("/sensitive", sensitive_app) 挂载,
因此对外路径是 /sensitive/api/monitor/*。建表不在此处(Mount 不转发 lifespan), 统一在主 app。
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlmodel import Session, delete as sql_delete, select

from app.common.taskrunner import BackgroundTaskRunner
from app.config import get_config
from app.db import engine
from app.sensitive.models import Leak, MonitorLog, MonitorTask
from app.sensitive.orchestrator import run_monitor

cfg = get_config()
runner = BackgroundTaskRunner()  # 监测领域独立的任务执行器(与仿冒站互不干扰)

_SEV_RANK = {"high": 3, "mid": 2, "low": 1, "": 0}


# ── 请求 / 响应模型 ──────────────────────────────────────
class MonitorTaskCreate(BaseModel):
    brand_keywords: str = ""
    domains: str = ""
    email_suffixes: str = ""
    internal_markers: str = ""
    ai_prompt: str = ""


class LeakPatch(BaseModel):
    manual_label: str  # unset/confirmed/false_positive/pending


class MonitorTaskOut(BaseModel):
    id: int
    brand_keywords: str
    domains: str
    email_suffixes: str
    internal_markers: str
    ai_prompt: str
    status: str
    message: str
    leak_count: int
    created_at: str
    updated_at: str


class LeakOut(BaseModel):
    id: int
    task_id: int
    source: str
    locator: str
    title: str
    snippet: str
    url: str
    leak_type: str
    verdict: str
    severity: str
    confidence: float
    reason: str
    manual_label: str
    created_at: str


def _task_out(t: MonitorTask) -> MonitorTaskOut:
    return MonitorTaskOut(
        id=t.id, brand_keywords=t.brand_keywords, domains=t.domains,
        email_suffixes=t.email_suffixes, internal_markers=t.internal_markers,
        ai_prompt=t.ai_prompt or "", status=t.status, message=t.message,
        leak_count=t.leak_count,
        created_at=t.created_at.isoformat() if t.created_at else "",
        updated_at=t.updated_at.isoformat() if t.updated_at else "",
    )


def _leak_out(lk: Leak) -> LeakOut:
    return LeakOut(
        id=lk.id, task_id=lk.task_id, source=lk.source, locator=lk.locator,
        title=lk.title, snippet=lk.snippet, url=lk.url, leak_type=lk.leak_type,
        verdict=lk.verdict, severity=lk.severity, confidence=round(lk.confidence, 4),
        reason=lk.reason, manual_label=lk.manual_label,
        created_at=lk.created_at.isoformat() if lk.created_at else "",
    )


sensitive_app = FastAPI(title="SensitiveMonitoring")


@sensitive_app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@sensitive_app.post("/api/monitor/tasks", response_model=MonitorTaskOut)
async def create_task(body: MonitorTaskCreate):
    fields = [body.brand_keywords, body.domains, body.email_suffixes, body.internal_markers]
    if not any(f.strip() for f in fields):
        raise HTTPException(400, "至少填写一类目标关键字")

    db = Session(engine)
    try:
        task = MonitorTask(
            brand_keywords=body.brand_keywords.strip(),
            domains=body.domains.strip(),
            email_suffixes=body.email_suffixes.strip(),
            internal_markers=body.internal_markers.strip(),
            ai_prompt=body.ai_prompt.strip(),
            status="pending",
        )
        db.add(task)
        db.commit()
        db.refresh(task)
    finally:
        db.close()

    runner.start(task.id, lambda evt: run_monitor(task, cfg, evt))
    return _task_out(task)


@sensitive_app.get("/api/monitor/tasks", response_model=list[MonitorTaskOut])
def list_tasks(limit: int = 20, offset: int = 0):
    db = Session(engine)
    stmt = select(MonitorTask).order_by(MonitorTask.created_at.desc()).offset(offset).limit(limit)
    results = db.exec(stmt).all()
    db.close()
    return [_task_out(t) for t in results]


@sensitive_app.get("/api/monitor/tasks/{task_id}", response_model=MonitorTaskOut)
def get_task(task_id: int):
    db = Session(engine)
    task = db.get(MonitorTask, task_id)
    db.close()
    if not task:
        raise HTTPException(404)
    return _task_out(task)


@sensitive_app.get("/api/monitor/tasks/{task_id}/leaks")
def list_leaks(
    task_id: int,
    severity: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    page: int = 1,
    per_page: int = 100,
):
    db = Session(engine)
    stmt = select(Leak).where(Leak.task_id == task_id)
    if severity:
        stmt = stmt.where(Leak.severity == severity)
    if verdict:
        stmt = stmt.where(Leak.verdict == verdict)
    if label:
        stmt = stmt.where(Leak.manual_label == label)
    rows = db.exec(stmt).all()
    db.close()
    # 按敏感等级(高>中>低)再按置信度排序
    rows.sort(key=lambda lk: (_SEV_RANK.get(lk.severity, 0), lk.confidence), reverse=True)
    total = len(rows)
    start = (page - 1) * per_page
    page_rows = rows[start:start + per_page]
    return {
        "items": [_leak_out(lk) for lk in page_rows],
        "total": total, "page": page, "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


@sensitive_app.get("/api/monitor/tasks/{task_id}/logs")
def task_logs(task_id: int, since_id: int = 0, limit: int = 200):
    db = Session(engine)
    stmt = select(MonitorLog).where(
        MonitorLog.task_id == task_id, MonitorLog.id > since_id,
    ).order_by(MonitorLog.id.asc()).limit(limit)
    rows = db.exec(stmt).all()
    db.close()
    return [{"id": r.id, "level": r.level, "message": r.message,
             "ts": r.created_at.isoformat() if r.created_at else ""} for r in rows]


@sensitive_app.patch("/api/monitor/leaks/{leak_id}", response_model=LeakOut)
def update_leak(leak_id: int, body: LeakPatch):
    valid = {"unset", "confirmed", "false_positive", "pending"}
    if body.manual_label not in valid:
        raise HTTPException(400, f"manual_label 须为 {'/'.join(valid)}")
    db = Session(engine)
    lk = db.get(Leak, leak_id)
    if not lk:
        db.close()
        raise HTTPException(404)
    lk.manual_label = body.manual_label
    db.commit()
    db.refresh(lk)
    db.close()
    return _leak_out(lk)


@sensitive_app.post("/api/monitor/tasks/{task_id}/stop", response_model=MonitorTaskOut)
def stop_task(task_id: int):
    db = Session(engine)
    task = db.get(MonitorTask, task_id)
    if not task:
        db.close()
        raise HTTPException(404)
    if task.status not in ("running", "pending"):
        db.close()
        raise HTTPException(400, "只能停止运行中/等待中的任务")
    runner.cancel(task_id)
    task.status = "done"
    task.message = "用户停止"
    task.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(task)
    db.close()
    return _task_out(task)


@sensitive_app.delete("/api/monitor/tasks/{task_id}")
def delete_task(task_id: int):
    db = Session(engine)
    task = db.get(MonitorTask, task_id)
    if not task:
        db.close()
        raise HTTPException(404)
    runner.cancel(task_id)
    # 删线索 + 日志 + 任务(两张子表都 FK monitortask.id)
    db.exec(sql_delete(Leak).where(Leak.task_id == task_id))
    db.exec(sql_delete(MonitorLog).where(MonitorLog.task_id == task_id))
    db.delete(task)
    db.commit()
    db.close()
    return {"ok": True}


@sensitive_app.get("/api/monitor/tasks/{task_id}/export")
def export_csv(task_id: int):
    db = Session(engine)
    rows = db.exec(select(Leak).where(Leak.task_id == task_id)).all()
    db.close()
    rows.sort(key=lambda lk: (_SEV_RANK.get(lk.severity, 0), lk.confidence), reverse=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "source", "locator", "title", "leak_type", "verdict", "severity",
        "confidence", "reason", "url", "manual_label",
    ])
    for lk in rows:
        writer.writerow([
            lk.source, lk.locator, lk.title, lk.leak_type, lk.verdict, lk.severity,
            lk.confidence, lk.reason, lk.url, lk.manual_label,
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=leaks_{task_id}.csv"},
    )


# ── 前端页面 ─────────────────────────────────────────────
_static_dir = Path(__file__).resolve().parent / "static"


@sensitive_app.get("/")
def index():
    return FileResponse(_static_dir / "index.html")
