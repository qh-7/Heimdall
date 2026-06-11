"""来源包。导入各来源模块以触发 @register 注册。

阶段2 起逐步实装 web / code; netdisk / intel 为占位(默认关闭)。
"""
import sys
import traceback

from app.sensitive.sources import base  # noqa: F401

_SOURCES = ["web", "code", "netdisk", "intel"]
for _name in _SOURCES:
    try:
        __import__(f"app.sensitive.sources.{_name}")
    except ModuleNotFoundError:
        pass  # 该来源尚未实装(阶段2 之前), 跳过
    except Exception:
        print(f"[WARN] Failed to load leak source '{_name}':", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
