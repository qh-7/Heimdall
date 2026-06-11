"""配置加载: 读取 config.yaml (回退 config.example.yaml), 支持环境变量覆盖 key。"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _deep_get(d: dict, path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


class Config:
    """对 yaml 配置的薄封装, 提供点路径取值与环境变量覆盖。"""

    # 环境变量 -> 配置点路径, 便于不改文件就注入密钥
    _ENV_MAP = {
        "FOFA_KEY": "fofa.key",
        "HUNTER_KEY": "hunter.key",
        "EXA_KEY": "exa.key",
        "LLM_KEY": "llm.key",
        "LLM_BASE_URL": "llm.base_url",
        "LLM_MODEL": "llm.model",
        "GITHUB_TOKEN": "sensitive.code.github_token",
        "ZONE_KEY": "sensitive.intel.key",
    }

    def __init__(self, data: dict):
        self._data = data
        self._apply_env()

    def _apply_env(self) -> None:
        for env, path in self._ENV_MAP.items():
            val = os.environ.get(env)
            if not val:
                continue
            parts = path.split(".")
            cur = self._data
            for p in parts[:-1]:
                cur = cur.setdefault(p, {})
            cur[parts[-1]] = val

    def get(self, path: str, default: Any = None) -> Any:
        return _deep_get(self._data, path, default)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    @property
    def raw(self) -> dict:
        return self._data

    def abspath(self, path: str) -> Path:
        """相对路径基于项目根目录解析。"""
        p = Path(path)
        return p if p.is_absolute() else ROOT / p


@lru_cache(maxsize=1)
def get_config() -> Config:
    cfg_path = ROOT / "config.yaml"
    if not cfg_path.exists():
        cfg_path = ROOT / "config.example.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Config(data)
