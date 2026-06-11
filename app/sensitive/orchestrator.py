"""监测编排器: 串联 发现(多源并发) → 按 locator 去重 → 入库 → AI 研判 全流程。

与仿冒站的 pipeline/orchestrator 同构但独立: 无行为分析、无加权评分; 泄露线索逐条研判,
按「定位」去重, 不跨源归并。结果流式入库, 支持 cancel_evt 协作式取消。
"""
from __future__ import annotations

import asyncio
import json
import time
import traceback
from datetime import datetime, timezone

from sqlmodel import Session, delete, select

from app.common.tasklog import log_task
from app.config import Config, get_config
from app.db import engine
from app.sensitive.models import Leak, MonitorLog, MonitorTask
from app.sensitive.sources.base import iter_enabled_sources

_SEV_RANK = {"high": 3, "mid": 2, "low": 1, "": 0}


def _cancelled(evt) -> bool:
    return evt is not None and evt.is_set()


def _log(db: Session, task_id: int, msg: str, level: str = "info") -> None:
    log_task(task_id, msg, level, db=db, log_model=MonitorLog)


def _set_status(db: Session, task_id: int, status: str, msg: str, **extra) -> None:
    t = db.get(MonitorTask, task_id)
    if not t:
        raise RuntimeError(f"MonitorTask {task_id} not found")
    t.status = status
    t.message = msg
    t.updated_at = datetime.now(timezone.utc)
    for k, v in extra.items():
        setattr(t, k, v)
    db.commit()


def _commit_leaks(db: Session, task_id: int, leaks: list[Leak]) -> None:
    """原子写入线索: 先删后插, 单次 commit。"""
    db.exec(delete(Leak).where(Leak.task_id == task_id))
    for lk in leaks:
        lk.id = None
        lk.task_id = task_id
        db.add(lk)
    db.commit()


def _update_leaks(db: Session, task_id: int, leaks: list[Leak]) -> None:
    """按 locator 把研判结果增量写回 DB。"""
    existing = db.exec(select(Leak).where(Leak.task_id == task_id)).all()
    by_loc = {lk.locator: lk for lk in existing}
    for lk in leaks:
        ex = by_loc.get(lk.locator)
        if ex:
            ex.leak_type = lk.leak_type
            ex.verdict = lk.verdict
            ex.severity = lk.severity
            ex.confidence = lk.confidence
            ex.reason = lk.reason
    db.commit()


async def _run_one_source(src, task, cancel_evt) -> tuple[str, list, str]:
    if _cancelled(cancel_evt):
        return (src.name, [], "已取消")
    t0 = time.monotonic()
    try:
        hits = await src.search(task)
        return (src.name, hits, f"{time.monotonic() - t0:.1f}s")
    except Exception as e:
        return (src.name, [], f"{type(e).__name__}: {str(e)[:100]}")


async def run_monitor(task: MonitorTask, cfg: Config | None = None,
                      cancel_evt=None) -> None:
    if cfg is None:
        cfg = get_config()

    db = Session(engine)
    task_id = task.id
    try:
        _log(db, task_id, "═══ 监测启动 ═══")
        _set_status(db, task_id, "running", "发现阶段")

        sources = list(iter_enabled_sources(cfg))
        _log(db, task_id, f"目标关键字: {', '.join(task.all_keywords()[:8])}")
        _log(db, task_id, f"来源({len(sources)}): {', '.join(s.name for s in sources) or '无'}")

        # ── Step 1: 发现 ─────────────────────────────────────
        hits = []
        coros = [_run_one_source(s, task, cancel_evt) for s in sources]
        for coro in asyncio.as_completed(coros):
            if _cancelled(cancel_evt):
                _set_status(db, task_id, "done", "用户停止")
                return
            name, hs, err = await coro
            hits.extend(hs)
            _log(db, task_id, f"  {name}: {len(hs)}条 ({err})")

        # ── Step 2: 去重(按 locator) + 入库 ──────────────────
        seen: set[str] = set()
        leaks: list[Leak] = []
        for h in hits:
            if not h.locator or h.locator in seen:
                continue
            seen.add(h.locator)
            leaks.append(Leak(
                task_id=task_id, source=h.source, locator=h.locator,
                title=h.title, snippet=h.snippet, url=h.url,
                raw=json.dumps(h.extra, ensure_ascii=False),
            ))
        _log(db, task_id, f"去重后: {len(leaks)} 条线索")
        _commit_leaks(db, task_id, leaks)
        _set_status(db, task_id, "running", f"发现 {len(leaks)} 条线索", leak_count=len(leaks))

        if not leaks:
            _set_status(db, task_id, "done", "未发现线索")
            return
        if _cancelled(cancel_evt):
            _set_status(db, task_id, "done", "用户停止")
            return

        # ── Step 3: AI 研判 (阶段3 接入 denoise) ─────────────
        try:
            from app.sensitive import denoise
            t0 = time.monotonic()
            _log(db, task_id, f"── AI 研判 ({len(leaks)}条) ──")
            leaks = await denoise.judge(leaks, task, cfg)
            _update_leaks(db, task_id, leaks)
            _log(db, task_id, f"研判完成 ({time.monotonic() - t0:.1f}s)")
        except ImportError:
            _log(db, task_id, "研判模块未就绪, 跳过", "warn")
        except Exception as e:
            _log(db, task_id, f"AI 研判失败: {e}", "error")

        # ── 完成 ─────────────────────────────────────────────
        high = sum(1 for lk in leaks if lk.severity == "high")
        mid = sum(1 for lk in leaks if lk.severity == "mid")
        _set_status(db, task_id, "done",
                    f"完成: {len(leaks)}条 (高危{high} 中{mid})", leak_count=len(leaks))
        _log(db, task_id, f"═══ 完成: {len(leaks)}条 (高危{high} 中{mid}) ═══")

    except Exception:
        msg = traceback.format_exc()[-500:]
        _log(db, task_id, f"异常: {msg}", "error")
        db2 = Session(engine)
        try:
            _set_status(db2, task_id, "failed", f"异常: {msg[-200:]}")
        finally:
            db2.close()
    finally:
        db.close()
