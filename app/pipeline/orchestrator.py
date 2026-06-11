"""流水线编排器: 串联 发现→过滤→降噪→行为分析→评分 全流程。

结果流式推送: 过滤后立即入库, 每步更新 DB, 前端实时可见。
支持 cancel_evt 检查以响应停止请求。
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import traceback
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.config import Config, get_config
from app.db import engine
from app.models import Candidate, Task
from app.pipeline import behavior, denoise, filtering, scoring
from app.pipeline.discovery.base import iter_enabled_sources
from app.pipeline.tasklog import log_task


def _cancelled(evt: threading.Event | None) -> bool:
    return evt is not None and evt.is_set()


def _log(db: Session, task_id: int, msg: str, level: str = "info") -> None:
    """复用 orchestrator 自己的 Session 写一条任务日志。"""
    log_task(task_id, msg, level, db=db)


def _set_status(db: Session, task_id: int, status: str, msg: str, **extra) -> Task:
    t = db.get(Task, task_id)
    if not t:
        raise RuntimeError(f"Task {task_id} not found")
    t.status = status
    t.message = msg
    t.updated_at = datetime.now(timezone.utc)
    for k, v in extra.items():
        setattr(t, k, v)
    db.commit()
    return t


def _commit_candidates(db: Session, task_id: int, candidates: list[Candidate]) -> None:
    """原子写入候选: 先删后插, 单次 commit。"""
    from sqlmodel import delete
    db.exec(delete(Candidate).where(Candidate.task_id == task_id))
    for c in candidates:
        c.id = None   # 清自增ID让DB重新分配
        c.task_id = task_id
        db.add(c)
    db.commit()


def _update_candidates(db: Session, task_id: int, candidates: list[Candidate]) -> None:
    """增量更新候选的 AI/行为/评分字段。按 domain 匹配。"""
    existing = db.exec(
        select(Candidate).where(Candidate.task_id == task_id)
    ).all()
    by_domain = {c.domain: c for c in existing}
    for c in candidates:
        ex = by_domain.get(c.domain)
        if ex:
            ex.llm_verdict = c.llm_verdict
            ex.llm_reason = c.llm_reason
            ex.llm_confidence = c.llm_confidence
            ex.behavior_flags = c.behavior_flags
            ex.screenshot_path = c.screenshot_path
            ex.final_url = c.final_url
            ex.title = c.title or ex.title
            ex.icon_match = c.icon_match
            ex.score = c.score
    db.commit()


async def _run_one_source(src, keywords, task, cancel_evt) -> tuple[str, list, str]:
    if _cancelled(cancel_evt):
        return (src.name, [], "已取消")
    t0 = time.monotonic()
    try:
        hits = await src.search(keywords, task)
        elapsed = time.monotonic() - t0
        return (src.name, hits, f"{elapsed:.1f}s")
    except Exception as e:
        elapsed = time.monotonic() - t0
        detail = str(e)[:100]
        return (src.name, [], f"{type(e).__name__}: {detail}")


async def run_task(task: Task, cfg: Config | None = None,
                   cancel_evt: threading.Event | None = None) -> None:
    if cfg is None:
        cfg = get_config()

    db = Session(engine)
    task_id = task.id
    try:
        _log(db, task_id, "═══ 流水线启动 ═══")
        _set_status(db, task_id, "running", "发现阶段")

        keywords = task.keywords_list()
        sources = list(iter_enabled_sources(cfg))
        _log(db, task_id, f"关键词({len(keywords)}): {', '.join(keywords[:5])}{'...' if len(keywords)>5 else ''}")
        _log(db, task_id, f"发现源({len(sources)}): {', '.join(s.name for s in sources)}")

        if not sources:
            _log(db, task_id, "无可用发现源, 任务失败", "error")
            _set_status(db, task_id, "failed", "无可用发现源")
            return

        # ── Step 1: 发现 ─────────────────────────────────────
        _log(db, task_id, "── 开始发现 ──")
        coros = [_run_one_source(src, keywords, task, cancel_evt) for src in sources]
        all_hits = []
        done_count = 0
        for coro in asyncio.as_completed(coros):
            if _cancelled(cancel_evt):
                _log(db, task_id, "收到停止信号")
                _set_status(db, task_id, "done", "用户停止")
                return
            name, hits, err = await coro
            done_count += 1
            all_hits.extend(hits)
            _log(db, task_id, f"  {name}: {len(hits)}条 ({err})")

        _log(db, task_id, f"发现完成: {len(all_hits)} 条")

        # ── Step 2: 过滤 + 入库 ──────────────────────────────
        candidates = filtering.filter_and_merge(all_hits, task, cfg)
        _log(db, task_id, f"过滤后: {len(candidates)} 个候选域名")
        # ★ 流式: 过滤完立刻入库
        _commit_candidates(db, task_id, candidates)
        _set_status(db, task_id, "running",
                    f"过滤后 {len(candidates)} 个候选",
                    candidate_count=len(candidates))

        if not candidates:
            _set_status(db, task_id, "done", "未发现可疑")
            return

        if _cancelled(cancel_evt):
            _set_status(db, task_id, "done", "用户停止")
            return

        # ── Step 3: LLM 降噪 ─────────────────────────────────
        _log(db, task_id, f"── AI 降噪 ({len(candidates)}个) ──")
        try:
            t0 = time.monotonic()
            candidates = await denoise.denoise(candidates, task, cfg)
            _log(db, task_id, f"AI 降噪完成 ({time.monotonic()-t0:.1f}s)")
            _update_candidates(db, task_id, candidates)
            _set_status(db, task_id, "running", f"AI降噪完成 ({len(candidates)}个)")
        except Exception as e:
            _log(db, task_id, f"AI 降噪失败: {e}", "error")

        if _cancelled(cancel_evt):
            _set_status(db, task_id, "done", "用户停止")
            return

        # ── Step 4: 行为分析 ─────────────────────────────────
        conc = cfg.get("behavior.max_concurrency", 20)
        _log(db, task_id, f"── 行为分析 ({len(candidates)}个, 并发{conc}) ──")
        try:
            t0 = time.monotonic()
            candidates = await behavior.analyze(candidates, task, cfg, task_id)
            _log(db, task_id, f"行为分析完成 ({time.monotonic()-t0:.1f}s)")
            _update_candidates(db, task_id, candidates)
            _set_status(db, task_id, "running", f"行为分析完成 ({len(candidates)}个)")
        except Exception as e:
            _log(db, task_id, f"行为分析失败: {e}", "error")

        if _cancelled(cancel_evt):
            _set_status(db, task_id, "done", "用户停止")
            return

        # ── Step 5: 评分 ─────────────────────────────────────
        _log(db, task_id, "── 评分 ──")
        candidates = scoring.score_all(candidates, cfg)
        _update_candidates(db, task_id, candidates)

        high = sum(1 for c in candidates if c.score >= 50)
        mid = sum(1 for c in candidates if 20 <= c.score < 50)
        _log(db, task_id, f"═══ 完成: {len(candidates)}个候选 (高{high} 中{mid}) ═══")
        _set_status(db, task_id, "done",
                    f"完成: {len(candidates)}个 (高{high} 中{mid})",
                    candidate_count=len(candidates))

    except Exception:
        msg = traceback.format_exc()[-500:]
        _log(db, task_id, f"异常: {msg}", "error")
        db2 = Session(engine)
        try:
            _set_status(db2, task_id, "failed", f"异常: {msg[-200:]}")
        except Exception as e:
            print(f"  failed to update status: {e}", file=sys.stderr, flush=True)
        finally:
            db2.close()
    finally:
        db.close()
