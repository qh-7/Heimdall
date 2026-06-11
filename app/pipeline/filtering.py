"""三层黑名单过滤 + 多源归并。

输入: 各发现源的 RawHit 列表
输出: 去重归并后的 Candidate 列表(未入库)
- IP 黑名单: 命中丢弃
- 域名白名单: 官方域名 + 配置白名单, 命中丢弃
- 标题黑名单: 标题含关键词丢弃
- 归并: 按注册域名合并, 累积命中源(多源 = 强信号)
"""
from __future__ import annotations

import json

from app.config import Config
from app.models import Candidate
from app.pipeline.discovery.base import RawHit
from app.pipeline.utils import is_official, registered_domain


def filter_and_merge(hits: list[RawHit], task, cfg: Config) -> list[Candidate]:
    official = task.domains_list()
    ip_black = set(cfg.get("filter.ip_blacklist", []) or [])
    title_black = [t.lower() for t in (cfg.get("filter.title_blacklist", []) or [])]
    domain_white = [d.lower() for d in (cfg.get("filter.domain_whitelist", []) or [])]
    # 白名单等价于"官方", 复用 is_official 的子域匹配
    whitelist = official + domain_white

    merged: dict[str, Candidate] = {}
    for h in hits:
        if not h.host:
            continue
        if h.ip and h.ip in ip_black:
            continue
        if is_official(h.host, whitelist):
            continue
        title = (h.title or "").lower()
        if title and any(b in title for b in title_black):
            continue

        rd = registered_domain(h.host)
        if not rd:
            continue

        cand = merged.get(rd)
        if cand is None:
            cand = Candidate(
                task_id=task.id, domain=rd, host=h.host, ip=h.ip,
                port=h.port, title=h.title, icon_hash=h.icon_hash,
                final_url=h.url, sources=json.dumps([h.source]),
                icon_match=bool(h.extra.get("icon_match")),
            )
            # 携带证书时间等附加信息进 behavior_flags 的种子
            if h.extra.get("not_before"):
                cand.behavior_flags = json.dumps({"cert_not_before": h.extra["not_before"]})
            merged[rd] = cand
        else:
            srcs = set(json.loads(cand.sources))
            srcs.add(h.source)
            cand.sources = json.dumps(sorted(srcs))
            # 补全空字段, 取信息更全的命中
            cand.ip = cand.ip or h.ip
            cand.port = cand.port or h.port
            cand.title = cand.title or h.title
            cand.icon_hash = cand.icon_hash or h.icon_hash
            cand.final_url = cand.final_url or h.url
            cand.icon_match = cand.icon_match or bool(h.extra.get("icon_match"))
            # 第二源以后也要补全证书时间
            if h.extra.get("not_before") and "cert_not_before" not in json.loads(cand.behavior_flags):
                flags = json.loads(cand.behavior_flags)
                flags["cert_not_before"] = h.extra["not_before"]
                cand.behavior_flags = json.dumps(flags)

    return list(merged.values())
