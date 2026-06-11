"""代码托管搜索来源(GitHub Code Search)。检索公开仓库中含目标关键字的代码/配置,
发现误传到 GitHub 的密钥、内部配置、源代码。

API: GET https://api.github.com/search/code?q=...
  Header: Authorization: Bearer <token>(必需, 匿名不可用代码搜索),
          Accept: application/vnd.github.text-match+json(返回命中片段)
速率限制约 10 次/分钟, 关键字间串行并在 403/429 时停止而非重试。

定位(locator) = "仓库全名:文件路径"。
"""
from __future__ import annotations

import httpx

from app.sensitive.sources.base import LeakHit, LeakSource, register

_SNIPPET_MAX = 500


@register
class CodeSource(LeakSource):
    name = "code"
    enabled_path = "sensitive.code.enabled"

    def _token(self) -> str:
        return self.cfg.get("sensitive.code.github_token", "") or ""

    def is_enabled(self) -> bool:
        return super().is_enabled() and bool(self._token())

    async def search(self, task) -> list[LeakHit]:
        per_page = int(self.cfg.get("sensitive.code.per_page", 30))
        timeout = self.cfg.get("general.http_timeout", 20)
        headers = {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        seen: set[str] = set()
        results: list[LeakHit] = []
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            for kw in task.all_keywords():
                try:
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": f'"{kw}"', "per_page": per_page},
                    )
                    if resp.status_code in (403, 429):
                        break  # 触发速率限制, 带着已有结果返回
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    continue
                for item in data.get("items", []):
                    repo = (item.get("repository") or {}).get("full_name", "")
                    path = item.get("path", "")
                    locator = f"{repo}:{path}"
                    if not repo or locator in seen:
                        continue
                    seen.add(locator)
                    # text-match 片段拼成证据
                    frags = [m.get("fragment", "") for m in item.get("text_matches", [])]
                    results.append(LeakHit(
                        source=self.name, locator=locator,
                        title=f"{repo}/{path}",
                        snippet="\n…\n".join(f for f in frags if f)[:_SNIPPET_MAX],
                        url=item.get("html_url", ""),
                        extra={"keyword": kw, "repo": repo, "path": path},
                    ))
        return results
