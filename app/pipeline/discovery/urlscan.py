"""URLScan.io 发现源 (免费社区 tier)。

URLScan 是一个大规模 URL 扫描服务, 提供社区 API 搜索已扫描页面。
API: GET https://urlscan.io/api/v1/search/?q=品牌词&size=100
返回扫描结果(含页面截图缩略图URL、标题、最终URL等)。
无需 API key (有速率限制, ~10 req/min)。
"""
from __future__ import annotations

import httpx

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.utils import is_official, normalize_host, clean_keywords


@register
class UrlscanSource(DiscoverySource):
    name = "urlscan"
    enabled_path = "urlscan.enabled"

    def is_enabled(self) -> bool:
        return bool(self.cfg.get("urlscan.enabled", False))

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        base = self.cfg.get("urlscan.base_url", "https://urlscan.io")
        timeout = self.cfg.get("general.http_timeout", 20)
        official = task.domains_list()
        ua = self.cfg.get("general.user_agent", "")
        size = int(self.cfg.get("urlscan.size", 100))

        seen: set[str] = set()
        results: list[RawHit] = []
        headers = {"User-Agent": ua} if ua else {}

        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            for kw in clean_keywords(keywords):
                try:
                    resp = await client.get(f"{base}/api/v1/search/",
                                            params={"q": kw, "size": size})
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    continue

                for item in data.get("results", []):
                    page = item.get("page", {})
                    url = page.get("url", "")
                    host = normalize_host(url)
                    if not host or host in seen or is_official(host, official):
                        continue
                    seen.add(host)
                    # URLScan 自带恶意评分
                    verdicts = item.get("verdicts", {})
                    malicious = verdicts.get("overall", {}).get("malicious", False)
                    tags = item.get("tags", [])
                    results.append(RawHit(
                        host=host, source="urlscan", url=url,
                        title=page.get("title", ""),
                        ip=page.get("ip", ""),
                        extra={
                            "malicious": malicious,
                            "tags": tags[:10],
                        },
                    ))
        return results
