"""AI 研判: 用大模型对泄露线索逐条定性(研判结论/敏感等级/泄露类型), 去误报。

调用 OpenAI 兼容的 /chat/completions(复用顶层 llm 配置段), 要求模型返回 JSON:
  {"verdict":"confirmed|suspected|irrelevant","severity":"high|mid|low",
   "leak_type":"credential|source_code|document|database|secret|other",
   "confidence":0-1,"reason":"..."}
并发受限; 单条失败不影响其它线索(留空 verdict, 前端按"未研判"展示)。
与仿冒站的 pipeline/denoise.py 同构但独立: 锚点是四类目标关键字而非品牌+官方域名。
"""
from __future__ import annotations

import asyncio
import json
import re

import httpx

from app.config import Config
from app.sensitive.models import Leak, MonitorTask

_VERDICTS = {"confirmed", "suspected", "irrelevant"}
_SEVERITIES = {"high", "mid", "low"}
_LEAK_TYPES = {"credential", "source_code", "document", "database", "secret", "other"}

_SYSTEM = (
    "你是数据泄露研判分析师。给定目标单位的四类目标关键字(单位名/品牌词、域名、"
    "邮箱后缀、内部特征串), 以及一条来自互联网的疑似泄露线索(来源/标题/证据片段/URL), "
    "判断它是否是该单位本不应公开的数据泄露。"
    "只输出 JSON, 不要多余文字, 格式: "
    '{"verdict":"confirmed|suspected|irrelevant","severity":"high|mid|low",'
    '"leak_type":"credential|source_code|document|database|secret|other",'
    '"confidence":0到1的小数,"reason":"简短中文理由"}。'
    "判定要点: 线索是否与目标单位相关(以目标关键字为锚, 同名无关单位算 irrelevant); "
    "内容是否本应非公开(官网新闻/公开文档/产品介绍算 irrelevant); "
    "敏感程度看危害(账号口令/密钥/数据库=high, 内部文档/源代码视内容 mid~high, "
    "仅提及内部系统名等弱信号=low)。证据不足时给 suspected 并降低 confidence。"
)


def _build_user_prompt(lk: Leak, task: MonitorTask) -> str:
    prompt = (
        f"单位名/品牌词: {', '.join(task.brand_list()) or '(未提供)'}\n"
        f"域名: {', '.join(task.domain_list()) or '(未提供)'}\n"
        f"邮箱后缀: {', '.join(task.email_suffix_list()) or '(未提供)'}\n"
        f"内部特征串: {', '.join(task.marker_list()) or '(未提供)'}\n"
        f"--- 泄露线索 ---\n"
        f"来源类型: {lk.source}\n"
        f"定位: {lk.locator}\n"
        f"标题: {lk.title or '(空)'}\n"
        f"URL: {lk.url or '(无)'}\n"
        f"证据片段:\n{lk.snippet or '(空)'}\n"
    )
    if task.ai_prompt:
        prompt += f"\n【用户研判背景】{task.ai_prompt}"
    return prompt


def _parse_json(text: str) -> dict:
    """从模型输出中稳健提取 JSON 对象。"""
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:
        return {}


def _apply(lk: Leak, parsed: dict) -> None:
    verdict = str(parsed.get("verdict", ""))
    severity = str(parsed.get("severity", ""))
    leak_type = str(parsed.get("leak_type", ""))
    lk.verdict = verdict if verdict in _VERDICTS else ""
    lk.severity = severity if severity in _SEVERITIES else ""
    lk.leak_type = leak_type if leak_type in _LEAK_TYPES else "other"
    lk.reason = str(parsed.get("reason", ""))[:500]
    try:
        lk.confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0))))
    except (TypeError, ValueError):
        lk.confidence = 0.0


def _update_leak_db(task_id: int, lk: Leak) -> None:
    """即时把单条研判结果按 locator 写回 DB, 前端轮询可实时看到。"""
    try:
        from sqlmodel import Session, select

        from app.db import engine as _eng
        db = Session(_eng)
        existing = db.exec(
            select(Leak).where(Leak.task_id == task_id, Leak.locator == lk.locator)
        ).first()
        if existing:
            existing.leak_type = lk.leak_type
            existing.verdict = lk.verdict
            existing.severity = lk.severity
            existing.confidence = lk.confidence
            existing.reason = lk.reason
            db.commit()
        db.close()
    except Exception:
        pass


async def _judge_one(client: httpx.AsyncClient, cfg: Config, lk: Leak,
                     task: MonitorTask, sem: asyncio.Semaphore,
                     fail_count: list) -> None:
    payload = {
        "model": cfg.get("llm.model", ""),
        "temperature": cfg.get("llm.temperature", 0.0),
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _build_user_prompt(lk, task)},
        ],
    }
    base = cfg.get("llm.base_url", "").rstrip("/")
    async with sem:
        # 熔断检查须在拿到信号量后做(同 pipeline/denoise.py 的教训)
        if fail_count[0] >= 5:
            lk.reason = "(跳过: LLM 连续失败已熔断)"
            return
        try:
            resp = await client.post(f"{base}/chat/completions", json=payload)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            _apply(lk, _parse_json(content))
        except Exception as e:
            lk.verdict = ""
            lk.reason = f"(LLM调用失败: {type(e).__name__})"
            lk.confidence = 0.0
            fail_count[0] += 1
        else:
            _update_leak_db(task.id, lk)


async def judge(leaks: list[Leak], task: MonitorTask, cfg: Config) -> list[Leak]:
    """对线索批量做 AI 研判。未启用或缺 key 时原样返回。最多 200 条。"""
    if not cfg.get("llm.enabled") or not cfg.get("llm.key") or not cfg.get("llm.base_url"):
        return leaks

    timeout = cfg.get("general.http_timeout", 20)
    sem = asyncio.Semaphore(int(cfg.get("llm.max_concurrency", 4)))
    headers = {"Authorization": f"Bearer {cfg.get('llm.key')}",
               "Content-Type": "application/json"}
    limit = int(cfg.get("sensitive.judge_limit", 200))
    fail_count = [0]

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        await asyncio.gather(*[
            _judge_one(client, cfg, lk, task, sem, fail_count)
            for lk in leaks[:limit]
        ])
    return leaks
