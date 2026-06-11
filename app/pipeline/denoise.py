"""LLM 降噪: 用大模型判定候选是否疑似仿冒, 去误报。

调用 OpenAI 兼容的 /chat/completions, 要求模型返回 JSON:
  {"verdict": "phishing|suspicious|benign", "confidence": 0-1, "reason": "..."}
并发受限; 单条失败不影响其它候选(留空 verdict 由后续评分按无信号处理)。
"""
from __future__ import annotations

import asyncio
import json
import re

import httpx

from app.config import Config
from app.models import Candidate, Task

_SYSTEM = (
    "你是反钓鱼安全分析师。给定目标单位的品牌词与官方域名, 以及一个候选网站的"
    "域名/标题等信息, 判断该候选是否疑似仿冒(钓鱼/假冒)目标单位。"
    "只输出 JSON, 不要多余文字, 格式: "
    '{"verdict":"phishing|suspicious|benign","confidence":0到1的小数,"reason":"简短中文理由"}。'
    "判定要点: 域名是否仿冒官方(相似拼写/品牌词+无关后缀)、标题是否冒用品牌、"
    "是否明显为无关站点。证据不足时给 suspicious 并降低 confidence。"
)


def _build_user_prompt(cand: Candidate, brand_keywords: list[str], official: list[str], ai_prompt: str = "") -> str:
    prompt = (
        f"目标品牌词: {', '.join(brand_keywords)}\n"
        f"官方域名: {', '.join(official) if official else '(未提供)'}\n"
        f"--- 候选网站 ---\n"
        f"域名: {cand.domain}\n"
        f"主机: {cand.host}\n"
        f"标题: {cand.title or '(空)'}\n"
        f"IP: {cand.ip or '(未知)'}\n"
        f"命中来源: {cand.sources}\n"
    )
    if ai_prompt:
        prompt += f"\n【用户研判背景】{ai_prompt}"
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


def _update_candidate_db(task: Task, cand: Candidate) -> None:
    """即时更新单个候选的 AI 判定结果到 DB。"""
    try:
        from app.db import engine as _eng
        from sqlmodel import Session, select
        db = Session(_eng)
        existing = db.exec(
            select(Candidate).where(
                Candidate.task_id == task.id,
                Candidate.domain == cand.domain,
            )
        ).first()
        if existing:
            existing.llm_verdict = cand.llm_verdict
            existing.llm_reason = cand.llm_reason
            existing.llm_confidence = cand.llm_confidence
            db.commit()
        db.close()
    except Exception:
        pass


async def _judge_one(client: httpx.AsyncClient, cfg: Config, cand: Candidate,
                     brand_keywords: list[str], official: list[str],
                     sem: asyncio.Semaphore, fail_count: list,
                     ai_prompt: str = "") -> None:
    base = cfg.get("llm.base_url", "").rstrip("/")
    model = cfg.get("llm.model", "")
    payload = {
        "model": model,
        "temperature": cfg.get("llm.temperature", 0.0),
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _build_user_prompt(cand, brand_keywords, official, ai_prompt)},
        ],
    }
    async with sem:
        # 熔断检查必须在拿到信号量、即将发请求时做; 放在 gather 入口处无效
        # (所有协程开局会在任何失败被记录前就一起通过检查)。
        if fail_count[0] >= 5:
            cand.llm_verdict = ""
            cand.llm_reason = "(跳过: LLM 连续失败已熔断)"
            cand.llm_confidence = 0.0
            return
        try:
            resp = await client.post(f"{base}/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = _parse_json(content)
            cand.llm_verdict = str(parsed.get("verdict", ""))[:20]
            cand.llm_reason = str(parsed.get("reason", ""))[:500]
            try:
                cand.llm_confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0))))
            except (TypeError, ValueError):
                cand.llm_confidence = 0.0
        except Exception as e:
            cand.llm_verdict = ""
            cand.llm_reason = f"(LLM调用失败: {type(e).__name__})"
            cand.llm_confidence = 0.0
            fail_count[0] += 1


async def denoise(candidates: list[Candidate], task, cfg: Config) -> list[Candidate]:
    """对候选批量做 LLM 判定。未启用或缺 key 时原样返回。并发执行, 最多 200 条。"""
    if not cfg.get("llm.enabled") or not cfg.get("llm.key") or not cfg.get("llm.base_url"):
        return candidates

    brand = task.keywords_list()
    official = task.domains_list()
    timeout = cfg.get("general.http_timeout", 10)
    sem = asyncio.Semaphore(int(cfg.get("llm.max_concurrency", 4)))
    headers = {"Authorization": f"Bearer {cfg.get('llm.key')}",
               "Content-Type": "application/json"}

    # 按多源优先级排序, 取前 200
    cands = sorted(candidates, key=lambda c: -len(json.loads(c.sources)))[:200]
    fail_count = [0]
    done_count = [0]
    total = len(cands)
    ai_prompt = task.ai_prompt or ""

    async def _judge_one_fast(c):
        if fail_count[0] >= 5:
            return
        await _judge_one(client, cfg, c, brand, official, sem, fail_count, ai_prompt)
        done_count[0] += 1
        if done_count[0] % 50 == 0:
            import sys
            print(f"  AI降噪: {done_count[0]}/{total}", file=sys.stderr, flush=True)
        # ★ 即时写 DB: 每条判定结果立即可见
        _update_candidate_db(task, c)

    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        await asyncio.gather(*[_judge_one_fast(c) for c in cands])
    return candidates
