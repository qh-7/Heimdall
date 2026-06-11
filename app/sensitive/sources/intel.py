"""暗网/泄露情报来源(零零信安 0.zone)。用目标关键字检索暗网数据/泄露情报库,
发现挂网售卖或暗网流传的目标单位数据。

API: POST {base_url}/api/data/  (JSON body 鉴权)
  body: {"query": "...", "query_type": "darknet", "page": N, "pagesize": N,
         "zone_key_id": "<key>"}
返回 JSON: {"code": 0, "message": "success", "total": N, "data": [{...}, ...]}
code 非 0 视为失败(key 无效/配额耗尽等)。

记录字段因情报类型而异, 解析做宽容处理(多候选字段取第一个非空)。
定位(locator) = "0zone:<记录ID>", 无 ID 时回退到 URL/标题哈希。
"""
from __future__ import annotations

import hashlib

import httpx

from app.sensitive.sources.base import LeakHit, LeakSource, register

_SNIPPET_MAX = 500


def _first(item: dict, *keys: str) -> str:
    """按优先级取第一个非空字段, 容忍不同情报类型的字段差异。"""
    for k in keys:
        v = item.get(k)
        if v:
            return str(v)
    return ""


@register
class IntelSource(LeakSource):
    name = "intel"
    enabled_path = "sensitive.intel.enabled"

    def _key(self) -> str:
        return self.cfg.get("sensitive.intel.key", "") or ""

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self._key())

    async def search(self, task) -> list[LeakHit]:
        base = self.cfg.get("sensitive.intel.base_url", "https://0.zone").rstrip("/")
        query_type = self.cfg.get("sensitive.intel.query_type", "darknet")
        pagesize = int(self.cfg.get("sensitive.intel.pagesize", 40))
        timeout = self.cfg.get("general.http_timeout", 20)

        seen: set[str] = set()
        results: list[LeakHit] = []
        async with httpx.AsyncClient(timeout=timeout) as client:
            for kw in task.all_keywords():
                try:
                    resp = await client.post(f"{base}/api/data/", json={
                        "query": kw,
                        "query_type": query_type,
                        "page": 1,
                        "pagesize": pagesize,
                        "zone_key_id": self._key(),
                    })
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    continue  # 单关键字失败不致命
                if str(data.get("code", "")) not in ("0", "200"):
                    # key 无效/配额耗尽对所有关键字都一样, 直接抛给 orchestrator 记日志
                    raise RuntimeError(f"0.zone: {data.get('message', 'unknown error')}")
                for item in data.get("data") or []:
                    title = _first(item, "title", "event_name", "name")
                    url = _first(item, "url", "detail_url", "source_url", "to_new_url")
                    rec_id = _first(item, "_id", "id", "uuid")
                    if not rec_id:
                        digest = hashlib.md5((url or title or repr(item)).encode()).hexdigest()
                        rec_id = digest[:16]
                    locator = f"0zone:{rec_id}"
                    if locator in seen:
                        continue
                    seen.add(locator)
                    snippet = _first(item, "content", "body", "description",
                                     "hacked_data", "detail")
                    results.append(LeakHit(
                        source=self.name, locator=locator,
                        title=title, snippet=snippet[:_SNIPPET_MAX], url=url,
                        extra={
                            "keyword": kw,
                            "query_type": query_type,
                            "release_time": _first(item, "release_time", "event_time",
                                                   "create_time"),
                        },
                    ))
        return results
