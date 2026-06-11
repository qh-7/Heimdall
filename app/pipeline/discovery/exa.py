"""Exa(WebSearch) 发现源。品牌词联网搜, 补充搜索引擎可见的仿冒站。

API: POST {base_url}/search  (Header: x-api-key)
  body: {"query": "...", "numResults": N, "type": "keyword"}
返回 JSON: {"results": [{"url","title",...}, ...]}
"""
from __future__ import annotations

import httpx

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.utils import is_official, normalize_host, clean_keywords


@register
class ExaSource(DiscoverySource):
    name = "exa"
    enabled_path = "exa.enabled"

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self.cfg.get("exa.key"))

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        base = self.cfg.get("exa.base_url", "https://api.exa.ai")
        key = self.cfg.get("exa.key")
        num = int(self.cfg.get("exa.num_results", 30))
        timeout = self.cfg.get("general.http_timeout", 20)
        official = task.domains_list()
        headers = {"x-api-key": key, "Content-Type": "application/json"}

        seen: set[str] = set()
        results: list[RawHit] = []
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            for kw in clean_keywords(keywords):
                # 偏向找仿冒/登录页
                query = f"{kw} 官网 登录 OR {kw} login"
                try:
                    resp = await client.post(f"{base}/search", json={
                        "query": query, "numResults": num, "type": "keyword",
                    })
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    continue
                for item in data.get("results", []):
                    url = item.get("url", "")
                    host = normalize_host(url)
                    if not host or host in seen or is_official(host, official):
                        continue
                    seen.add(host)
                    results.append(RawHit(
                        host=host, source="exa", url=url,
                        title=item.get("title", ""),
                    ))
        return results
