"""发现源抽象接口与注册表。

每个数据源(FOFA/Hunter/crt.sh/Exa)实现 DiscoverySource, 返回统一的 RawHit。
orchestrator 通过 iter_enabled_sources() 拿到所有已启用的源并发执行。
新增数据源 = 新建一个模块 + @register, 不改动其它代码。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from app.config import Config


@dataclass
class RawHit:
    """单个发现源命中的原始记录, 字段尽量统一; 缺失留空。"""

    host: str  # 主机名或域名 (必填)
    source: str  # 命中来源标识, 如 fofa_kw / hunter / crtsh
    ip: str = ""
    port: str = ""
    title: str = ""
    url: str = ""
    icon_hash: str = ""
    extra: dict = field(default_factory=dict)


class DiscoverySource:
    """发现源基类。子类实现 search()。"""

    name: str = "base"
    # 配置中对应的开关路径, 例如 "fofa.enabled"
    enabled_path: str = ""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def is_enabled(self) -> bool:
        if not self.enabled_path:
            return True
        return bool(self.cfg.get(self.enabled_path, False))

    async def search(self, keywords: list[str], task) -> list[RawHit]:
        """根据品牌词(及任务上下文)返回命中列表。子类实现。"""
        raise NotImplementedError


# ── 注册表 ───────────────────────────────────────────────
_REGISTRY: list[type[DiscoverySource]] = []


def register(cls: type[DiscoverySource]) -> type[DiscoverySource]:
    _REGISTRY.append(cls)
    return cls


def iter_enabled_sources(cfg: Config) -> Iterable[DiscoverySource]:
    """实例化所有已启用且 key 就绪的发现源。"""
    for cls in _REGISTRY:
        src = cls(cfg)
        if src.is_enabled():
            yield src


def all_source_classes() -> list[type[DiscoverySource]]:
    return list(_REGISTRY)
