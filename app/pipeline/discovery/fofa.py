"""FOFA 发现源: 关键词查询 + icon_hash 查询。

API: GET {base_url}/api/v1/search/all
  key=...&qbase64=<base64(query)>&fields=host,ip,port,title,domain&size=N
返回 JSON: {"error": false, "results": [[host, ip, port, title, domain], ...]}

限速: 专业版 30次/分钟, 每请求间隔 2s
"""
from __future__ import annotations

import asyncio
import base64

import httpx

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.discovery.favicon import fetch_favicon_hash, guess_favicon_hash_from_site
from app.pipeline.tasklog import log_task
from app.pipeline.utils import is_official, clean_keywords

_FIELDS = "host,ip,port,title,domain"


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


@register
class FofaSource(DiscoverySource):
    name = "fofa"
    enabled_path = "fofa.enabled"

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self.cfg.get("fofa.key"))

    def _exclude_clause(self, official: list[str]) -> str:
        parts = [f'domain!="{d}"' for d in official if d]
        return (" && " + " && ".join(parts)) if parts else ""

    async def _query(self, client: httpx.AsyncClient, query: str, size: int) -> list[RawHit]:
        base = self.cfg.get("fofa.base_url", "https://fofa.info")
        params = {
            "key": self.cfg.get("fofa.key"),
            "qbase64": _qbase64(query),
            "fields": _FIELDS,
            "size": size,
        }
        resp = await client.get(f"{base}/api/v1/search/all", params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise RuntimeError(f"FOFA error: {data.get('errmsg')}")
        hits: list[RawHit] = []
        for row in data.get("results", []):
            host, ip, port, title, domain = (list(row) + [""] * 5)[:5]
            tag = "fofa_icon" if 'icon_hash=' in query else "fofa_kw"
            hits.append(RawHit(host=host or domain, source=tag, ip=ip,
                               port=str(port), title=title))
        return hits

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        size = int(self.cfg.get("fofa.size", 5000))
        official = task.domains_list()
        timeout = self.cfg.get("general.http_timeout", 20)
        excl = self._exclude_clause(official)
        clean_kw = clean_keywords(keywords)
        total = len(clean_kw)

        results: list[RawHit] = []
        seen_hosts: set[str] = set()
        async with httpx.AsyncClient(timeout=timeout) as client:
            # 1) 逐关键词查询
            for i, kw in enumerate(clean_kw):
                q = f'(title="{kw}" || body="{kw}"){excl}'
                try:
                    hits = await self._query(client, q, size)
                    for h in hits:
                        if h.host not in seen_hosts:
                            seen_hosts.add(h.host)
                            results.append(h)
                except Exception as e:
                    log_task(task.id, f"FOFA [{i+1}/{total}] '{kw[:15]}': {type(e).__name__}")

                # 进度日志每 20 个关键词
                if (i + 1) % 20 == 0:
                    log_task(task.id, f"FOFA 进度: {i+1}/{total} 关键词, {len(results)} 命中")

                # 限速: 30次/分钟 = 2s 间隔
                if i < total - 1:
                    await asyncio.sleep(2)

            # 2) icon_hash (如有官方域名)
            icon_hash = ""
            if task.favicon_url:
                icon_hash = await fetch_favicon_hash(task.favicon_url)
            if not icon_hash and official:
                icon_hash = await guess_favicon_hash_from_site(official[0])
            if icon_hash:
                q = f'icon_hash="{icon_hash}"{excl}'
                try:
                    icon_hits = await self._query(client, q, size)
                    for h in icon_hits:
                        if h.host not in seen_hosts and not is_official(h.host, official):
                            h.source = "fofa_icon"
                            h.extra["icon_match"] = True
                            results.append(h)
                except Exception as e:
                    log_task(task.id, f"FOFA icon_hash: {type(e).__name__}")

        return results
