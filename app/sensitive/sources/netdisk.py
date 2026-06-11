"""网盘文库搜索来源——占位。

MVP 暂无可靠的免费网盘搜索 API; 接入时实现 search() 并在 config 打开
sensitive.netdisk.enabled。定位(locator) = 分享链接。
"""
from __future__ import annotations

from app.sensitive.sources.base import LeakHit, LeakSource, register


@register
class NetdiskSource(LeakSource):
    name = "netdisk"
    enabled_path = "sensitive.netdisk.enabled"  # 默认 false, 配置打开前不参与监测

    async def search(self, task) -> list[LeakHit]:
        return []
