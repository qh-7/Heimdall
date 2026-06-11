"""官方 favicon 下载与 FOFA 风格 icon_hash 计算。

FOFA 的 icon_hash = mmh3.hash(base64.encodebytes(favicon_bytes))。
拿到官方站 favicon 的 hash 后, 用 FOFA `icon_hash="..."` 查全网克隆站。
"""
from __future__ import annotations

import base64

import httpx
import mmh3

from app.config import get_config

_cfg = get_config()


def compute_icon_hash(content: bytes) -> str:
    """按 FOFA 算法计算 favicon hash: mmh3.hash(base64.encodebytes(content))。

    注意必须用 encodebytes(每 76 字符插入换行 + 末尾换行), 与 FOFA/Shodan 一致;
    用 b64encode(单行)会得到不同的 mmh3 值, 导致 icon_hash 检索永远查不到克隆站。
    """
    b64 = base64.encodebytes(content)
    return str(mmh3.hash(b64))


async def fetch_favicon_hash(favicon_url: str) -> str:
    """下载 favicon 并返回其 icon_hash; 失败返回空串。"""
    if not favicon_url:
        return ""
    timeout = _cfg.get("general.http_timeout", 20)
    ua = _cfg.get("general.user_agent", "")
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     headers={"User-Agent": ua}) as client:
            resp = await client.get(favicon_url)
            resp.raise_for_status()
            if not resp.content:
                return ""
            return compute_icon_hash(resp.content)
    except Exception:
        return ""


async def guess_favicon_hash_from_site(site_url: str) -> str:
    """未显式给 favicon URL 时, 尝试 {origin}/favicon.ico。"""
    if not site_url:
        return ""
    if "://" not in site_url:
        site_url = "https://" + site_url
    origin = site_url.rstrip("/")
    # 去掉 path, 只取 scheme://host
    from urllib.parse import urlparse
    p = urlparse(origin)
    base = f"{p.scheme}://{p.netloc}"
    return await fetch_favicon_hash(f"{base}/favicon.ico")
