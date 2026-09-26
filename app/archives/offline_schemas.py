from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class OfflineExportRequest(BaseModel):
    since_package_code: str | None = Field(default=None, min_length=3, max_length=64)


class OfflinePackageDocument(BaseModel):
    """导入或预演时提交的完整离线包文档；结构与摘要由编解码层严格校验。"""

    document: dict[str, Any]


class ForkResolveRequest(BaseModel):
    resolution: Literal["keep_local", "apply_remote"]
    note: str = Field(default="", max_length=500)
