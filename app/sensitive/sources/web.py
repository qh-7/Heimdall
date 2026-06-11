"""通用网页搜索来源(Exa)。用目标关键字+泄露特征词联网搜, 发现搜索引擎可见的泄露线索。

API: POST {base_url}/search  (Header: x-api-key, 复用顶层 exa 段的 key/base_url)
  body: {"query": "...", "numResults": N, "type": "keyword", "contents": {"text": ...}}
返回 JSON: {"results": [{"url","title","text",...}, ...]}

定位(locator) = URL。
"""
from __future__ import annotations

import httpx

from app.sensitive.sources.base import LeakHit, LeakSource, register

# 与目标关键字组合的泄露特征词, 偏向召回"挂网的内部数据"
_LEAK_TERMS = "密码 OR 账号 OR 泄露 OR 内部 OR password OR leak"

_SNIPPET_MAX = 500


@register
class WebSource(LeakSource):
    name = "web"
    enabled_path = "sensitive.web.enabled"

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self.cfg.get("exa.key"))

    async def search(self, task) -> list[LeakHit]:
        base = self.cfg.get("exa.base_url", "https://api.exa.ai")
        key = self.cfg.get("exa.key")
        num = int(self.cfg.get("sensitive.web.num_results", 20))
        timeout = self.cfg.get("general.http_timeout", 20)
        headers = {"x-api-key": key, "Content-Type": "application/json"}

        seen: set[str] = set()
        results: list[LeakHit] = []
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            for kw in task.all_keywords():
                try:
                    resp = await client.post(f"{base}/search", json={
                        "query": f'"{kw}" {_LEAK_TERMS}',
                        "numResults": num,
                        "type": "keyword",
                        "contents": {"text": {"maxCharacters": _SNIPPET_MAX}},
                    })
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    continue  # 单关键字失败不致命, 与其它来源约定一致
                for item in data.get("results", []):
                    url = item.get("url", "")
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    results.append(LeakHit(
                        source=self.name, locator=url, url=url,
                        title=item.get("title") or "",
                        snippet=(item.get("text") or "")[:_SNIPPET_MAX],
                        extra={"keyword": kw},
                    ))
        return results
