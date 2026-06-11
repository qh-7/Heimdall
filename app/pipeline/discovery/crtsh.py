"""crt.sh 证书透明度发现源 (免费, 无需 key)。

查含品牌词的已签发证书 -> 提取 SAN 中的域名。
API: GET https://crt.sh/?q=%25品牌%25&output=json
返回 JSON 数组: [{"common_name","name_value","not_before",...}, ...]
"""
from __future__ import annotations

import httpx

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.utils import is_official, normalize_host


@register
class CrtShSource(DiscoverySource):
    name = "crtsh"
    enabled_path = "crtsh.enabled"

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        base = self.cfg.get("crtsh.base_url", "https://crt.sh")
        timeout = 8.0  # crt.sh 响应很慢, 短超时
        official = task.domains_list()
        ua = self.cfg.get("general.user_agent", "")
        kw_list = keywords[:5]  # 最多 5 个关键词

        seen: set[str] = set()
        results: list[RawHit] = []
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": ua}) as client:
            for kw in kw_list:
                try:
                    resp = await client.get(base, params={"q": f"%{kw}%", "output": "json"})
                    resp.raise_for_status()
                    rows = resp.json()
                except Exception:
                    continue
                for row in rows:
                    names = (row.get("name_value") or "").split("\n")
                    not_before = row.get("not_before", "")
                    for raw in names:
                        host = normalize_host(raw.replace("*.", ""))
                        if not host or host in seen or is_official(host, official):
                            continue
                        seen.add(host)
                        results.append(RawHit(
                            host=host, source="crtsh",
                            extra={"not_before": not_before},
                        ))
        return results
