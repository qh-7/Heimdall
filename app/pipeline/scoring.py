"""评分: 综合 favicon 匹配/品牌词/表单/支付/证书/跳转/多源/LLM 加权打分。

总分 >= threshold 视为"疑似仿冒"(在 Web 端高亮)。权重全部来自 config。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from app.config import Config
from app.models import Candidate


def _cert_is_recent(not_before: str, days: int = 30) -> bool:
    if not not_before:
        return False
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(not_before[:19], fmt).replace(tzinfo=timezone.utc)
            # 需 0 <= 天数 <= days; 缺下界会把未来日期(时钟偏差/伪造)误判为"新证书"。
            return 0 <= (datetime.now(timezone.utc) - dt).days <= days
        except ValueError:
            continue
    return False


def score_candidate(cand: Candidate, cfg: Config) -> int:
    w = cfg.get("scoring.weights", {}) or {}
    flags = json.loads(cand.behavior_flags) if cand.behavior_flags else {}
    sources = json.loads(cand.sources) if cand.sources else []

    score = 0
    if cand.icon_match:
        score += w.get("icon_exact", 40)
    if flags.get("brand_in_content"):
        score += w.get("brand_in_content", 20)
    if flags.get("login_form"):
        score += w.get("login_form", 15)
    if flags.get("payment"):
        score += w.get("payment", 10)
    if _cert_is_recent(flags.get("cert_not_before", "")):
        score += w.get("suspicious_cert", 10)
    if flags.get("redirect_offsite"):
        score += w.get("redirect_offsite", 5)
    if len(sources) >= 2:
        score += w.get("multi_source", 10)

    # LLM 置信度按比例叠加; benign 判定不加分
    llm_max = w.get("llm_max", 30)
    if cand.llm_verdict in ("phishing", "suspicious"):
        score += int(round(cand.llm_confidence * llm_max))

    cand.score = int(score)
    return cand.score


def score_all(candidates: list[Candidate], cfg: Config) -> list[Candidate]:
    for c in candidates:
        score_candidate(c, cfg)
    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates
