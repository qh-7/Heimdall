"""域名排列发现源: 基于品牌词生成可能的仿冒域名排列, DNS 验证存活。

策略:
  - 组合抢注: {kw}login, {kw}verify, {kw}安全, {kw}pay, {kw}app, login-{kw} ...
  - 覆盖常见 TLD: .com/.cn/.net/.top/.xyz/.vip/.shop 等
  - DNS 解析验证: 仅保留实际解析的域名, 去噪
  - 免费, 无需 API key, 但有速率限制(并发50)
"""
from __future__ import annotations

import asyncio
import socket

from app.pipeline.discovery.base import DiscoverySource, RawHit, register
from app.pipeline.utils import normalize_host, clean_keywords

# 优先 TLD (钓鱼最常用, 优先查)
_PRIORITY_TLD = ["com", "cn", "net", "top", "xyz", "cc", "vip", "shop"]

# 二级 TLD (仅用于关键组合)
_SECONDARY_TLD = ["org", "info", "site", "online", "club", "work", "live", "icu", "cyou"]

# 高价值组合后缀 (仅用于 .com/.cn)
_HIGH_VALUE_SUFFIX = ["login", "verify", "secure", "app", "pay", "安全", "登录", "认证"]

# 基于关键词的 typosquatting 变换 (通用)
_TYPO_RULES = [
    # 双写常见 (如金温->金金温)
    lambda s: s[0] + s,
    # 省略首字
    lambda s: s[1:] if len(s) > 1 else s,
]


def _generate_domains(keywords: list[str]) -> list[str]:
    """生成待查域名排列(限制数量以控制耗时)。"""
    domains: list[str] = []
    seen: set[str] = set()
    kw_clean = []
    for kw in clean_keywords(keywords):
        clean = kw
        for suffix in ["集团有限公司", "有限责任公司", "有限公司", "集团", "股份", "公司"]:
            if clean.endswith(suffix):
                clean = clean[:-len(suffix)]
        kw_clean.append(clean.strip())
        if clean != kw:
            kw_clean.append(kw.strip())

    all_kw = list(dict.fromkeys(k for k in kw_clean if k and len(k) >= 2))[:8]
    max_domains = 800  # 上限控制耗时

    for kw in all_kw:
        kw_lower = kw.lower()
        # 高价值: 组合后缀 x 优先TLD
        for sfx in _HIGH_VALUE_SUFFIX:
            for tld in _PRIORITY_TLD[:4]:
                for variant in [kw_lower + sfx, sfx + kw_lower]:
                    domain = f"{variant}.{tld}"
                    if domain not in seen:
                        seen.add(domain)
                        domains.append(domain)
                        if len(domains) >= max_domains: return domains
        # 裸关键词 x 所有优先TLD
        for tld in _PRIORITY_TLD:
            domain = f"{kw_lower}.{tld}"
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
                if len(domains) >= max_domains: return domains
        # Typosquatting 变体 x 主TLD
        for rule in _TYPO_RULES:
            variant = rule(kw_lower)
            if variant != kw_lower:
                for tld in _PRIORITY_TLD[:2]:
                    domain = f"{variant}.{tld}"
                    if domain not in seen:
                        seen.add(domain)
                        domains.append(domain)
                        if len(domains) >= max_domains: return domains

    return domains


async def _resolve(domain: str, timeout: float) -> str:
    """异步 DNS 解析(用线程池), 返回 IP 或空串。中文域名自动转 Punycode。
    用 asyncio.wait_for 强制超时, 避免 socket 默认 30s 阻塞线程池。"""
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""
    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, ascii_domain),
            timeout=timeout,
        )
        return result
    except Exception:
        return ""


@register
class PermutationSource(DiscoverySource):
    """域名排列 + DNS 验证源。不需要 API key, 但有速率限制。"""
    name = "permutation"
    enabled_path = "permutation.enabled"

    def is_enabled(self) -> bool:
        return bool(self.cfg.get("permutation.enabled", True))

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        domains = _generate_domains(keywords)
        if not domains:
            return []

        # DNS 并发验证, 限制并发数
        sem = asyncio.Semaphore(100)
        timeout = self.cfg.get("permutation.dns_timeout", 1.5)

        async def _check(d):
            async with sem:
                ip = await _resolve(d, timeout)
                if ip:
                    return RawHit(host=d, source="permutation", ip=ip)
                return None

        tasks = [asyncio.create_task(_check(d)) for d in domains]
        hits: list[RawHit] = []
        for coro in asyncio.as_completed(tasks):
            hit = await coro
            if hit:
                hits.append(hit)
        return hits
