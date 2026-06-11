"""数据模型: Task(任务) 与 Candidate(候选仿冒站)。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Task(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    brand_keywords: str  # 逗号分隔
    official_domains: str  # 逗号分隔
    favicon_url: str = ""
    ai_prompt: str = ""  # 用户自定义 AI 研判背景提示词
    status: str = "pending"  # pending / running / done / failed
    message: str = ""  # 失败原因或进度说明
    candidate_count: int = 0
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    def keywords_list(self) -> list[str]:
        return [k.strip() for k in self.brand_keywords.split(",") if k.strip()]

    def domains_list(self) -> list[str]:
        return [d.strip().lower() for d in self.official_domains.split(",") if d.strip()]


class Candidate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="task.id")
    domain: str = Field(index=True)  # 注册域名 (归并键)
    host: str = ""  # 完整主机名
    ip: str = ""
    port: str = ""
    title: str = ""
    sources: str = "[]"  # JSON 数组: 命中的发现源
    icon_hash: str = ""
    icon_match: bool = False  # favicon 是否与官方匹配

    llm_verdict: str = ""  # phishing / suspicious / benign / ""
    llm_reason: str = ""
    llm_confidence: float = 0.0

    behavior_flags: str = "{}"  # JSON: 表单/跳转/品牌词等特征
    screenshot_path: str = ""
    final_url: str = ""

    score: int = 0
    manual_label: str = "unset"  # unset / phishing / false_positive / pending

    created_at: datetime = Field(default_factory=_now)


class TaskLog(SQLModel, table=True):
    """实时日志: 记录流水线每个步骤的详细进度。"""
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True, foreign_key="task.id")
    level: str = "info"  # info / warn / error
    message: str = ""
    created_at: datetime = Field(default_factory=_now)
