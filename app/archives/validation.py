"""专利与技术秘密档案操作共用的领域校验。

接口会接收多个离线客户端的数据，因此把校验集中在可复用的小模块中，
避免路由层重复实现，并为导入与重放流程提供稳定的错误信息。
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.core.errors import ValidationError


_CODE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")


def require_code(value: str, field: str) -> str:
    """规范化并校验外部传入的档案编码。"""
    normalized = value.strip().upper()
    if not _CODE.fullmatch(normalized):
        raise ValidationError(f"{field}必须是 3-64 位大写档案编码")
    return normalized


def require_positive(value: float, field: str) -> float:
    """统一拒绝非数字、无穷、零和负数数量。"""
    number = float(value)
    if number != number or number in {float("inf"), float("-inf")} or number <= 0:
        raise ValidationError(f"{field}必须是正数")
    return number


def parse_timestamp(value: str, field: str = "时间") -> datetime:
    """解析 ISO-8601 时间，并返回带时区的值。"""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field}不是有效的 ISO-8601 时间") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field}必须包含时区")
    return parsed


def validate_window(start: str, end: str, *, fields: tuple[str, str] = ("开始时间", "结束时间")) -> tuple[datetime, datetime]:
    """校验包含端点的档案授权时间窗口。"""
    first = parse_timestamp(start, fields[0])
    last = parse_timestamp(end, fields[1])
    if last < first:
        raise ValidationError(f"{fields[1]}不能早于{fields[0]}")
    return first, last


def stable_payload(payload: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """创建用于审计摘要的确定性字符串表示。"""
    return tuple(sorted((str(key), repr(payload[key])) for key in payload))


def assert_same_payload(expected: dict[str, Any], actual: dict[str, Any]) -> None:
    """重放请求改变业务参数时抛出领域冲突。"""
    if stable_payload(expected) != stable_payload(actual):
        raise ValidationError("重放请求的业务参数与原记录不一致")
