"""Hunter(奇安信 hunter.qianxin.com) 发现源。

API: GET {base_url}/openApi/search
  api-key=...&search=<base64(query)>&page=1&page_size=100&is_web=1
查询语法: web.title="品牌" || web.body="品牌"
返回 JSON: {"code":200,"data":{"arr":[{"domain","ip","port","web_title","url"},...]}}
"""
from __future__ import annotations

import base64

import httpx

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.utils import is_official, normalize_host, clean_keywords


@register
class HunterSource(DiscoverySource):
    name = "hunter"
    enabled_path = "hunter.enabled"

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self.cfg.get("hunter.key"))

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        base = self.cfg.get("hunter.base_url", "https://hunter.qianxin.com")
        key = self.cfg.get("hunter.key")
        page_size = int(self.cfg.get("hunter.page_size", 100))
        timeout = self.cfg.get("general.http_timeout", 20)
        official = task.domains_list()

        results: list[RawHit] = []
        async with httpx.AsyncClient(timeout=timeout) as client:
            for kw in clean_keywords(keywords):
                query = f'web.title="{kw}" || web.body="{kw}"'
                search_b64 = base64.urlsafe_b64encode(query.encode()).decode()
                params = {
                    "api-key": key,
                    "search": search_b64,
                    "page": 1,
                    "page_size": page_size,
                    "is_web": 1,
                }
                try:
                    resp = await client.get(f"{base}/openApi/search", params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    if data.get("code") != 200:
                        continue
                    arr = (data.get("data") or {}).get("arr") or []
                    for item in arr:
                        host = normalize_host(item.get("domain") or item.get("url") or item.get("ip") or "")
                        if not host or is_official(host, official):
                            continue
                        results.append(RawHit(
                            host=host, source="hunter",
                            ip=item.get("ip", ""), port=str(item.get("port", "")),
                            title=item.get("web_title", ""), url=item.get("url", ""),
                        ))
                except Exception:
                    continue
        return results
