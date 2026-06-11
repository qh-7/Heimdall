"""发现源包。导入各源模块以触发 @register 注册。"""
import traceback, sys
from app.pipeline.discovery import base  # noqa: F401

_SOURCES = ["fofa", "hunter", "crtsh", "exa", "permutation", "urlscan"]
for _name in _SOURCES:
    try:
        __import__(f"app.pipeline.discovery.{_name}")
    except Exception:
        print(f"[WARN] Failed to load discovery source '{_name}':", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
