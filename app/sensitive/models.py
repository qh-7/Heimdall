"""数据模型: MonitorTask(监测任务) / Leak(泄露线索) / MonitorLog(实时日志)。

与仿冒站发现的 Task/Candidate/TaskLog 是各自独立的表, 共享同一 SQLite 文件与 metadata。
研判枚举一律存英文(verdict/severity/leak_type), 前端映射中文展示。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MonitorTask(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # 四类目标关键字, 均逗号分隔
    brand_keywords: str = ""       # 单位名/品牌词
    domains: str = ""              # 域名/子域名
    email_suffixes: str = ""       # 邮箱后缀(可含或不含 @)
    internal_markers: str = ""     # 内部特征串(系统名/项目代号/特征路径)
    ai_prompt: str = ""            # 自定义 AI 研判背景提示词
    status: str = "pending"        # pending / running / done / failed
    message: str = ""
    leak_count: int = 0
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    @staticmethod
    def _split(s: str) -> list[str]:
        return [x.strip() for x in (s or "").split(",") if x.strip()]

    def brand_list(self) -> list[str]:
        return self._split(self.brand_keywords)

    def domain_list(self) -> list[str]:
        return [d.lower() for d in self._split(self.domains)]

    def email_suffix_list(self) -> list[str]:
        return [s.lstrip("@").lower() for s in self._split(self.email_suffixes)]

    def marker_list(self) -> list[str]:
        return self._split(self.internal_markers)

    def all_keywords(self) -> list[str]:
        """去重后的全部关键字, 供来源构造查询。"""
        seen: list[str] = []
        for kw in self.brand_list() + self.domain_list() + self.email_suffix_list() + self.marker_list():
            if kw and kw not in seen:
                seen.append(kw)
        return seen


class Leak(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="monitortask.id")
    source: str = ""               # 来源类型: web / code / netdisk / intel
    locator: str = Field(default="", index=True)  # 去重键: URL / repo+path / 分享链接 / 记录ID
    title: str = ""
    snippet: str = ""              # 证据片段
    url: str = ""
    raw: str = "{}"                # JSON: 来源附加字段

    leak_type: str = ""            # credential/source_code/document/database/secret/other
    verdict: str = ""              # confirmed/suspected/irrelevant/""
    severity: str = ""             # high/mid/low/""
    confidence: float = 0.0
    reason: str = ""

    manual_label: str = "unset"    # unset/confirmed/false_positive/pending
    created_at: datetime = Field(default_factory=_now)


class MonitorLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="monitortask.id")
    level: str = "info"            # info/warn/error
    message: str = ""
    created_at: datetime = Field(default_factory=_now)
