"""FastAPI 应用: API 路由 + 静态前端。

路由:
  GET  /health
  POST /api/tasks              创建任务并启动后台流水线
  GET  /api/tasks              任务列表
  GET  /api/tasks/{id}         任务详情
  POST /api/tasks/{id}/stop    停止运行中的任务
  DELETE /api/tasks/{id}       删除任务及关联候选
  GET  /api/tasks/{id}/candidates  候选列表(分页/按评分排序)
  PATCH /api/candidates/{id}   人工标记
  GET  /api/tasks/{id}/export  CSV 导出
  GET  /api/screenshots/{name} 截图文件
"""
from __future__ import annotations

import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import Session, select, delete as sql_delete

from app.common.taskrunner import BackgroundTaskRunner
from app.config import get_config
from app.db import engine, init_db
from app.models import Candidate, Task, TaskLog
from app.pipeline.orchestrator import run_task

cfg = get_config()

# 后台任务执行器(线程 + 取消标志), 抽到 app.common 供两个领域共用
runner = BackgroundTaskRunner()


# ── 请求模型 ─────────────────────────────────────────────
class TaskCreate(BaseModel):
    brand_keywords: str  # 逗号分隔
    official_domains: str = ""  # 逗号分隔, 可选
    favicon_url: str = ""
    ai_prompt: str = ""  # 自定义 AI 研判背景提示词


class CandidatePatch(BaseModel):
    manual_label: str  # phishing / false_positive / pending


# ── 响应模型 ─────────────────────────────────────────────
class TaskOut(BaseModel):
    id: int
    brand_keywords: str
    official_domains: str
    favicon_url: str
    ai_prompt: str
    status: str
    message: str
    candidate_count: int
    created_at: str
    updated_at: str


class CandidateOut(BaseModel):
    id: int
    task_id: int
    domain: str
    host: str
    ip: str
    port: str
    title: str
    sources: str
    icon_hash: str
    icon_match: bool
    llm_verdict: str
    llm_reason: str
    llm_confidence: float
    behavior_flags: str
    screenshot_path: str
    final_url: str
    score: int
    manual_label: str
    created_at: str


def _task_out(t: Task) -> TaskOut:
    return TaskOut(
        id=t.id, brand_keywords=t.brand_keywords,
        official_domains=t.official_domains, favicon_url=t.favicon_url,
        ai_prompt=t.ai_prompt or "",
        status=t.status, message=t.message,
        candidate_count=t.candidate_count,
        created_at=t.created_at.isoformat() if t.created_at else "",
        updated_at=t.updated_at.isoformat() if t.updated_at else "",
    )


def _candidate_out(c: Candidate) -> CandidateOut:
    return CandidateOut(
        id=c.id, task_id=c.task_id, domain=c.domain, host=c.host,
        ip=c.ip, port=c.port, title=c.title, sources=c.sources,
        icon_hash=c.icon_hash, icon_match=c.icon_match,
        llm_verdict=c.llm_verdict, llm_reason=c.llm_reason,
        llm_confidence=round(c.llm_confidence, 4),
        behavior_flags=c.behavior_flags,
        screenshot_path=c.screenshot_path, final_url=c.final_url,
        score=c.score, manual_label=c.manual_label,
        created_at=c.created_at.isoformat() if c.created_at else "",
    )


# ── 应用 ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Heimdall", lifespan=lifespan)

# 敏感信息监测子应用(独立领域, 路径前缀 /sensitive, 建表仍统一走主 app 的 lifespan)
from app.sensitive.main import sensitive_app  # noqa: E402

app.mount("/sensitive", sensitive_app)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/tasks", response_model=TaskOut)
async def create_task(body: TaskCreate, bg: BackgroundTasks):
    kw = body.brand_keywords.strip()
    od = body.official_domains.strip()
    if not kw:
        raise HTTPException(400, "brand_keywords 不能为空")

    db = Session(engine)
    try:
        task = Task(
            brand_keywords=kw, official_domains=od,
            favicon_url=body.favicon_url.strip(),
            ai_prompt=body.ai_prompt.strip(),
            status="pending",
        )
        db.add(task)
        db.commit()
        db.refresh(task)
    finally:
        db.close()

    # 后台线程执行流水线 (线程内开独立 event loop)
    runner.start(task.id, lambda evt: run_task(task, cfg, evt))
    return _task_out(task)


@app.get("/api/tasks", response_model=list[TaskOut])
def list_tasks(limit: int = 20, offset: int = 0):
    db = Session(engine)
    stmt = select(Task).order_by(Task.created_at.desc()).offset(offset).limit(limit)
    results = db.exec(stmt).all()
    db.close()
    return [_task_out(t) for t in results]


@app.get("/api/tasks/{task_id}", response_model=TaskOut)
def get_task(task_id: int):
    db = Session(engine)
    task = db.get(Task, task_id)
    db.close()
    if not task:
        raise HTTPException(404)
    return _task_out(task)


@app.get("/api/tasks/{task_id}/candidates")
def list_candidates(
    task_id: int,
    min_score: Optional[int] = Query(None),
    label: Optional[str] = Query(None),
    ai_verdict: Optional[str] = Query(None),
    page: int = 1,
    per_page: int = 100,
):
    db = Session(engine)
    filters = [Candidate.task_id == task_id]
    if min_score is not None:
        filters.append(Candidate.score >= min_score)
    if label is not None:
        filters.append(Candidate.manual_label == label)
    if ai_verdict is not None:
        filters.append(Candidate.llm_verdict == ai_verdict)
    # 总数: 用 COUNT 查询, 不再 len(全部行) 把整表 ORM 化
    total = db.exec(select(func.count()).select_from(Candidate).where(*filters)).one()
    # 分页
    offset = (page - 1) * per_page
    results = db.exec(
        select(Candidate).where(*filters)
        .order_by(Candidate.score.desc())
        .offset(offset).limit(per_page)
    ).all()
    db.close()
    return {
        "items": [_candidate_out(c) for c in results],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


@app.patch("/api/candidates/{cand_id}", response_model=CandidateOut)
def update_candidate(cand_id: int, body: CandidatePatch):
    valid = {"phishing", "false_positive", "pending", "unset"}
    if body.manual_label not in valid:
        raise HTTPException(400, f"manual_label 须为 {'/'.join(valid)}")
    db = Session(engine)
    cand = db.get(Candidate, cand_id)
    if not cand:
        db.close()
        raise HTTPException(404)
    cand.manual_label = body.manual_label
    db.commit()
    db.refresh(cand)
    db.close()
    return _candidate_out(cand)


@app.get("/api/tasks/{task_id}/export")
def export_csv(task_id: int):
    db = Session(engine)
    candidates = db.exec(
        select(Candidate).where(Candidate.task_id == task_id).order_by(Candidate.score.desc())
    ).all()
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "domain", "host", "ip", "port", "title", "sources", "score",
        "icon_match", "llm_verdict", "llm_confidence", "llm_reason",
        "behavior_flags", "manual_label", "final_url",
    ])
    for c in candidates:
        writer.writerow([
            c.domain, c.host, c.ip, c.port, c.title, c.sources, c.score,
            c.icon_match, c.llm_verdict, c.llm_confidence, c.llm_reason,
            c.behavior_flags, c.manual_label, c.final_url,
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=heimdall_brand_{task_id}.csv"},
    )


@app.get("/api/screenshots/{name}")
def screenshot(name: str):
    # 防路径穿越: 禁特殊字符, 确认只在截图目录内
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(404)
    d = cfg.abspath(cfg.get("general.screenshot_dir", "app/data/screenshots"))
    fp = (d / name).resolve()
    if not str(fp).startswith(str(d.resolve())):
        raise HTTPException(404)
    if not fp.exists():
        raise HTTPException(404)
    return FileResponse(fp)


@app.get("/api/tasks/{task_id}/logs")
def task_logs(task_id: int, since_id: int = 0, limit: int = 200):
    """获取实时日志。since_id: 增量轮询(只返回新于该 ID 的日志)。"""
    db = Session(engine)
    stmt = select(TaskLog).where(
        TaskLog.task_id == task_id,
        TaskLog.id > since_id,
    ).order_by(TaskLog.id.asc()).limit(limit)
    rows = db.exec(stmt).all()
    db.close()
    return [{"id": r.id, "level": r.level, "message": r.message,
             "ts": r.created_at.isoformat() if r.created_at else ""} for r in rows]


@app.post("/api/tasks/{task_id}/stop", response_model=TaskOut)
async def stop_task(task_id: int):
    db = Session(engine)
    task = db.get(Task, task_id)
    if not task:
        db.close()
        raise HTTPException(404)
    if task.status not in ("running", "pending"):
        db.close()
        raise HTTPException(400, "只能停止运行中/等待中的任务")

    # 设置取消标志
    runner.cancel(task_id)

    task.status = "done"
    task.message = "用户停止"
    task.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(task)
    db.close()
    return _task_out(task)


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int):
    db = Session(engine)
    task = db.get(Task, task_id)
    if not task:
        db.close()
        raise HTTPException(404)

    # 如果正在运行则先取消
    runner.cancel(task_id)

    # 删候选 + 任务
    db.exec(sql_delete(Candidate).where(Candidate.task_id == task_id))
    db.delete(task)
    db.commit()
    db.close()
    return {"ok": True}


# ── 前端页面 (路由直出, 不走 StaticFiles 避免缓存) ─────
_static_dir = Path(__file__).resolve().parent / "static"


@app.get("/")
def index():
    index_path = _static_dir / "index.html"
    return FileResponse(index_path)

