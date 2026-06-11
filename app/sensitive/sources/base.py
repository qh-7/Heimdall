"""来源插件抽象与注册表。

每个来源实现 LeakSource, 返回统一的 LeakHit。orchestrator 通过 iter_enabled_sources()
拿到所有已启用的来源并发执行。新增来源 = 新建模块 + @register, 不改动其它代码。

与仿冒站发现的 discovery/base.py 同构, 但独立(不跨领域引用)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from app.config import Config


@dataclass
class LeakHit:
    """单个来源命中的一条疑似泄露记录, 字段尽量统一; 缺失留空。"""

    source: str                    # 来源类型: web / code / netdisk / intel
    locator: str                   # 去重键(同一来源内唯一定位)
    title: str = ""
    snippet: str = ""              # 证据片段
    url: str = ""
    extra: dict = field(default_factory=dict)


class LeakSource:
    """来源基类。子类实现 search()。"""

    name: str = "base"
    enabled_path: str = ""         # 配置中的开关路径, 如 "sensitive.web.enabled"

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def is_enabled(self) -> bool:
        if not self.enabled_path:
            return True
        return bool(self.cfg.get(self.enabled_path, False))

    async def search(self, task) -> list[LeakHit]:
        """根据监测任务的目标关键字返回命中列表。子类实现。"""
        raise NotImplementedError


# ── 注册表 ───────────────────────────────────────────────
_REGISTRY: list[type[LeakSource]] = []


def register(cls: type[LeakSource]) -> type[LeakSource]:
    _REGISTRY.append(cls)
    return cls


def iter_enabled_sources(cfg: Config) -> Iterable[LeakSource]:
    for cls in _REGISTRY:
        src = cls(cfg)
        if src.is_enabled():
            yield src
