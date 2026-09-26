"""离线移交包的导出、导入、分叉裁决与独立核对。

分支研发中心无法持续访问总部服务，只能定期导出移交包同步数据。本模块实现：

- 包结构：父包指针、负载摘要、链式包摘要与可选 HMAC 签名（``ARCHIVE_PACKAGE_KEY``）；
- 导出：以上一包为水位线收集新增档案、审批结果与载体变更，站点标识来自
  ``ARCHIVE_SITE_ID``（默认 ``HQ``）；
- 导入：预演（不落库，报告缺失依赖）→ 登记（staged）→ 逐条提交（每条一个事务），
  失败后可断点续传；同一包重复提交返回原批次结果，不重复写入；
- 依赖：父包缺失、前置批次/库位/档案缺失、前置版本未到达都会被识别并阻断，
  待前置包到达后可继续；
- 分叉：同一档案在两端被独立修改时保留本地与远端两条来源，进入人工裁决；
- 核对：独立重算摘要链、顺序、审计链、版本关系与当前有效状态。

同步边界：离线包只承载新增档案、审批结果与载体变更（库位转移）。分支对同步档案
的其他写操作（披露、借阅、处置等）不进入离线包，若因此造成版本分叉，会按分叉
流程进入人工裁决。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal, normalize_username
from app.database import transaction
from app.archives.repository import DossierRepository
from app.services.audit import AuditContext, AuditService

PACKAGE_CODE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
ORIGIN_SITE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,31}$")
ITEM_TYPES = ("intake_batch", "dossier_register", "approval_result", "vault_transfer")
APPROVAL_ACTIONS = ("access_loan", "disposal", "vault_reveal", "inventory_review_adjustment")
UNUSABLE_PASSWORD_HASH = "!offline-shadow-account"


class MissingDependencyError(Exception):
    """包内引用了总部尚未收到的前置数据（可恢复的阻断，不是数据错误）。"""

    def __init__(self, dependencies: list[dict[str, Any]]) -> None:
        self.dependencies = dependencies
        summary = "；".join(item["detail"] for item in dependencies)
        super().__init__(f"缺少前置依赖：{summary}")


# ---------------------------------------------------------------------------
# 包文档编解码与摘要
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def site_id() -> str:
    return os.getenv("ARCHIVE_SITE_ID", "HQ")


def package_signing_key() -> str | None:
    return os.getenv("ARCHIVE_PACKAGE_KEY") or None


def sign_digest(package_digest: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), package_digest.encode("utf-8"), hashlib.sha256).hexdigest()


def item_digest(item: dict[str, Any]) -> str:
    return sha256_text(
        canonical_json(
            {
                "index": item["index"],
                "type": item["type"],
                "key": item["key"],
                "payload": item["payload"],
            }
        )
    )


def compute_payload_digest(items: list[dict[str, Any]]) -> str:
    return sha256_text(
        canonical_json(
            [
                {
                    "index": item["index"],
                    "type": item["type"],
                    "key": item["key"],
                    "payload": item["payload"],
                    "digest": item_digest(item),
                }
                for item in items
            ]
        )
    )


def compute_package_digest(header: dict[str, Any], payload_digest: str) -> str:
    return sha256_text(
        canonical_json(
            {
                "package_code": header["package_code"],
                "origin_site": header["origin_site"],
                "sequence": header["sequence"],
                "parent_package_code": header["parent_package_code"],
                "parent_digest": header["parent_digest"],
                "payload_digest": payload_digest,
            }
        )
    )


def build_package_document(
    *,
    package_code: str,
    origin_site: str,
    sequence: int,
    parent_package_code: str | None,
    parent_digest: str | None,
    created_at: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """由头部与条目构造完整包文档（含摘要与可选签名）。"""
    header = {
        "package_code": package_code,
        "origin_site": origin_site,
        "sequence": sequence,
        "parent_package_code": parent_package_code,
        "parent_digest": parent_digest,
        "created_at": created_at,
    }
    payload_digest = compute_payload_digest(items)
    package_digest = compute_package_digest(header, payload_digest)
    document = {
        **header,
        "items": items,
        "payload_digest": payload_digest,
        "package_digest": package_digest,
    }
    key = package_signing_key()
    if key:
        document["signature"] = sign_digest(package_digest, key)
    return document


def _require_string(value: Any, field: str, *, max_length: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValidationError(f"包条目字段 {field} 必须是 1-{max_length} 字符的非空字符串")
    return value


def _require_int(value: Any, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"包条目字段 {field} 必须是不小于 {minimum} 的整数")
    return value


def _require_quantity(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"包条目字段 {field} 必须是正数")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")) or number <= 0:
        raise ValidationError(f"包条目字段 {field} 必须是正数")
    return number


def _validate_payload(item_type: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError(f"包条目 {item_type} 的 payload 必须是对象")
    if item_type == "intake_batch":
        _require_string(payload.get("intake_code"), "intake_code")
        _require_string(payload.get("project_code"), "project_code")
        _require_int(payload.get("expected_count"), "expected_count", minimum=1)
        _require_string(payload.get("received_by"), "received_by")
        _require_string(payload.get("occurred_at"), "occurred_at", max_length=40)
    elif item_type == "dossier_register":
        _require_string(payload.get("dossier_code"), "dossier_code")
        _require_string(payload.get("intake_code"), "intake_code")
        _require_string(payload.get("asset_type"), "asset_type")
        _require_quantity(payload.get("quantity"), "quantity")
        _require_string(payload.get("unit"), "unit", max_length=20)
        if payload.get("vault_code") is not None:
            _require_string(payload.get("vault_code"), "vault_code")
        if payload.get("custody_user") is not None:
            _require_string(payload.get("custody_user"), "custody_user")
        _require_string(payload.get("occurred_at"), "occurred_at", max_length=40)
    elif item_type == "vault_transfer":
        _require_string(payload.get("dossier_code"), "dossier_code")
        _require_string(payload.get("to_vault_code"), "to_vault_code")
        _require_int(payload.get("base_version"), "base_version", minimum=1)
        _require_string(payload.get("transfer_code"), "transfer_code")
        _require_string(payload.get("reason"), "reason", max_length=500)
        _require_string(payload.get("occurred_at"), "occurred_at", max_length=40)
    elif item_type == "approval_result":
        _require_string(payload.get("request_code"), "request_code")
        if payload.get("action_type") not in APPROVAL_ACTIONS:
            raise ValidationError(f"包条目 approval_result 的 action_type 必须是 {APPROVAL_ACTIONS} 之一")
        _require_string(payload.get("dossier_code"), "dossier_code")
        _require_string(payload.get("requested_by"), "requested_by")
        _require_int(payload.get("required_approvals"), "required_approvals", minimum=2)
        _require_string(payload.get("expires_at"), "expires_at", max_length=40)
        decisions = payload.get("decisions")
        if not isinstance(decisions, list):
            raise ValidationError("包条目 approval_result 的 decisions 必须是数组")
        for decision in decisions:
            if not isinstance(decision, dict):
                raise ValidationError("包条目 approval_result 的 decisions 元素必须是对象")
            _require_string(decision.get("approver"), "decisions.approver")
            if decision.get("decision") not in ("approve", "reject"):
                raise ValidationError("包条目 approval_result 的 decision 必须是 approve 或 reject")
            if not isinstance(decision.get("comment", ""), str):
                raise ValidationError("包条目 approval_result 的 comment 必须是字符串")
            _require_string(decision.get("decided_at"), "decisions.decided_at", max_length=40)
    else:  # pragma: no cover - 入口已限制类型
        raise ValidationError(f"未知的包条目类型：{item_type}")
    return payload


def validate_package_document(document: Any) -> dict[str, Any]:
    """校验包文档结构、负载摘要、链式包摘要与签名，返回规范化结果。"""
    if not isinstance(document, dict):
        raise ValidationError("离线包必须是 JSON 对象")
    header = {
        "package_code": document.get("package_code"),
        "origin_site": document.get("origin_site"),
        "sequence": document.get("sequence"),
        "parent_package_code": document.get("parent_package_code"),
        "parent_digest": document.get("parent_digest"),
        "created_at": document.get("created_at"),
    }
    _require_string(header["package_code"], "package_code")
    if not PACKAGE_CODE_PATTERN.fullmatch(header["package_code"]):
        raise ValidationError("package_code 必须是 3-64 位大写包编号")
    _require_string(header["origin_site"], "origin_site", max_length=32)
    if not ORIGIN_SITE_PATTERN.fullmatch(header["origin_site"]):
        raise ValidationError("origin_site 必须是 2-32 位大写站点标识")
    _require_int(header["sequence"], "sequence", minimum=1)
    _require_string(header["created_at"], "created_at", max_length=40)
    if (header["parent_package_code"] is None) != (header["parent_digest"] is None):
        raise ValidationError("parent_package_code 与 parent_digest 必须同时存在或同时为空")
    if header["parent_package_code"] is not None:
        _require_string(header["parent_package_code"], "parent_package_code")
        _require_string(header["parent_digest"], "parent_digest", max_length=64)
        if header["sequence"] < 2:
            raise ValidationError("携带父包指针的包序号必须大于 1")
    items = document.get("items")
    if not isinstance(items, list):
        raise ValidationError("离线包 items 必须是数组")
    if len(items) > 10_000:
        raise ValidationError("单个离线包最多容纳 10000 个条目")
    normalized_items: list[dict[str, Any]] = []
    for position, raw in enumerate(items):
        if not isinstance(raw, dict):
            raise ValidationError(f"离线包第 {position} 个条目必须是对象")
        index = raw.get("index")
        _require_int(index, "index", minimum=0)
        if index != position:
            raise ValidationError("离线包条目 index 必须从 0 开始连续编号")
        item_type = raw.get("type")
        if item_type not in ITEM_TYPES:
            raise ValidationError(f"离线包条目类型必须是 {ITEM_TYPES} 之一")
        key = _require_string(raw.get("key"), "key")
        payload = _validate_payload(item_type, raw.get("payload"))
        normalized_items.append({"index": index, "type": item_type, "key": key, "payload": payload})
    keys = [item["key"] for item in normalized_items]
    if len(set(keys)) != len(keys):
        raise ValidationError("离线包条目 key 不能重复")
    payload_digest = compute_payload_digest(normalized_items)
    if document.get("payload_digest") != payload_digest:
        raise ValidationError("离线包负载摘要校验失败，包内容可能被篡改")
    package_digest = compute_package_digest(header, payload_digest)
    if document.get("package_digest") != package_digest:
        raise ValidationError("离线包链式摘要校验失败，包内容可能被篡改")
    signature = document.get("signature")
    key = package_signing_key()
    if key:
        if not isinstance(signature, str) or not hmac.compare_digest(signature, sign_digest(package_digest, key)):
            raise ValidationError("离线包签名校验失败")
    return {
        "header": header,
        "items": normalized_items,
        "payload_digest": payload_digest,
        "package_digest": package_digest,
        "signature": signature if isinstance(signature, str) else None,
    }


# ---------------------------------------------------------------------------
# 存储层
# ---------------------------------------------------------------------------


class OfflinePackageRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    # -- 包 ---------------------------------------------------------------

    def create_package(
        self,
        *,
        package_code: str,
        origin_site: str,
        sequence: int,
        parent_package_code: str | None,
        parent_digest: str | None,
        payload_digest: str,
        package_digest: str,
        signature: str | None,
        direction: str,
        status: str,
        item_count: int,
        now: str,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO offline_packages(
                   package_code,origin_site,sequence,parent_package_code,parent_digest,
                   payload_digest,package_digest,signature,direction,status,item_count,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                package_code, origin_site, sequence, parent_package_code, parent_digest,
                payload_digest, package_digest, signature, direction, status, item_count, now,
            ),
        )
        return self.get(cursor.lastrowid)

    def get(self, package_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM offline_packages WHERE id=?", (package_id,)).fetchone()
        if row is None:
            raise NotFoundError("离线包不存在")
        return dict(row)

    def by_digest(self, package_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM offline_packages WHERE package_digest=?", (package_digest,)
        ).fetchone()
        return dict(row) if row else None

    def by_code(self, origin_site: str, package_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM offline_packages WHERE origin_site=? AND package_code=?",
            (origin_site, package_code),
        ).fetchone()
        return dict(row) if row else None

    def find_by_code(self, package_code: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM offline_packages WHERE package_code=? ORDER BY id", (package_code,)
        ).fetchall()
        return [dict(row) for row in rows]

    def latest(self, origin_site: str, *, direction: str | None = None, status: str | None = None) -> dict[str, Any] | None:
        clauses = ["origin_site=?"]
        params: list[Any] = [origin_site]
        if direction:
            clauses.append("direction=?")
            params.append(direction)
        if status:
            clauses.append("status=?")
            params.append(status)
        row = self.connection.execute(
            f"SELECT * FROM offline_packages WHERE {' AND '.join(clauses)} ORDER BY sequence DESC LIMIT 1",
            tuple(params),
        ).fetchone()
        return dict(row) if row else None

    def list(self, *, origin_site: str | None, status: str | None, direction: str | None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("origin_site", origin_site), ("status", status), ("direction", direction)):
            if value:
                clauses.append(f"{column}=?")
                params.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            "SELECT * FROM offline_packages" + where + " ORDER BY origin_site, sequence", tuple(params)
        ).fetchall()
        return [dict(row) for row in rows]

    def committed_sequences(self, origin_site: str) -> list[int]:
        rows = self.connection.execute(
            "SELECT sequence FROM offline_packages WHERE origin_site=? AND direction='imported' AND status='committed' ORDER BY sequence",
            (origin_site,),
        ).fetchall()
        return [int(row[0]) for row in rows]

    def update_status(
        self,
        package_id: int,
        status: str,
        now: str,
        *,
        error_message: str | None = None,
        committed_at: str | None = None,
    ) -> dict[str, Any]:
        self.connection.execute(
            """UPDATE offline_packages SET status=?,error_message=?,
               committed_at=COALESCE(?,committed_at) WHERE id=?""",
            (status, error_message, committed_at, package_id),
        )
        return self.get(package_id)

    def save_result(self, package_id: int, result: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE offline_packages SET result_json=? WHERE id=?",
            (json.dumps(result, ensure_ascii=False, sort_keys=True), package_id),
        )

    # -- 条目 ---------------------------------------------------------------

    def add_item(
        self,
        package_id: int,
        *,
        index: int,
        item_type: str,
        key: str,
        payload: dict[str, Any],
        status: str,
        now: str,
    ) -> None:
        self.connection.execute(
            """INSERT INTO offline_package_items(
                   package_id,item_index,item_type,item_key,payload_json,payload_digest,status,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                package_id,
                index,
                item_type,
                key,
                canonical_json(payload),
                item_digest({"index": index, "type": item_type, "key": key, "payload": payload}),
                status,
                now,
                now,
            ),
        )

    def items(self, package_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM offline_package_items WHERE package_id=? ORDER BY item_index", (package_id,)
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def pending_items(self, package_id: int) -> list[dict[str, Any]]:
        return [item for item in self.items(package_id) if item["status"] in ("pending", "failed")]

    def update_item(
        self,
        item_id: int,
        status: str,
        now: str,
        *,
        resource_type: str | None = None,
        resource_id: str | int | None = None,
        error_message: str | None = None,
    ) -> None:
        self.connection.execute(
            """UPDATE offline_package_items SET status=?,resource_type=COALESCE(?,resource_type),
               resource_id=COALESCE(?,resource_id),error_message=?,updated_at=? WHERE id=?""",
            (
                status,
                resource_type,
                str(resource_id) if resource_id is not None else None,
                error_message,
                now,
                item_id,
            ),
        )

    # -- 分叉 ---------------------------------------------------------------

    def create_fork(
        self,
        *,
        dossier_id: int,
        package_id: int,
        item_id: int,
        reason: str,
        local_snapshot: dict[str, Any],
        incoming_payload: dict[str, Any],
        now: str,
    ) -> dict[str, Any]:
        fork_code = f"FRK-{uuid.uuid4().hex[:12]}"
        cursor = self.connection.execute(
            """INSERT INTO dossier_forks(
                   fork_code,dossier_id,package_id,item_id,reason,local_snapshot_json,
                   incoming_payload_json,state,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,'pending',?,?)""",
            (
                fork_code,
                dossier_id,
                package_id,
                item_id,
                reason,
                canonical_json(local_snapshot),
                canonical_json(incoming_payload),
                now,
                now,
            ),
        )
        return self.get_fork(cursor.lastrowid)

    def get_fork(self, fork_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM dossier_forks WHERE id=?", (fork_id,)).fetchone()
        if row is None:
            raise NotFoundError("分叉记录不存在")
        return self._fork_dict(row)

    def _fork_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["local_snapshot"] = json.loads(item.pop("local_snapshot_json"))
        item["incoming_payload"] = json.loads(item.pop("incoming_payload_json"))
        return item

    def list_forks(self, state: str | None = None, package_id: int | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if state:
            clauses.append("state=?")
            params.append(state)
        if package_id:
            clauses.append("package_id=?")
            params.append(package_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            "SELECT * FROM dossier_forks" + where + " ORDER BY id DESC", tuple(params)
        ).fetchall()
        return [self._fork_dict(row) for row in rows]

    def resolve_fork(self, fork_id: int, state: str, note: str, resolved_by: int | None, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE dossier_forks SET state=?,resolution_note=?,resolved_by=?,resolved_at=?,updated_at=? WHERE id=?",
            (state, note, resolved_by, now, now, fork_id),
        )
        return self.get_fork(fork_id)


# ---------------------------------------------------------------------------
# 共享小工具
# ---------------------------------------------------------------------------


def ensure_shadow_user(connection: sqlite3.Connection, origin_site: str, username: str, now: str) -> dict[str, Any]:
    """为离线来源站点的人员建立不可登录的影子账号，保留真实身份用于审计与审批链。"""
    base = normalize_username(username)
    candidate = f"off.{origin_site.lower()}.{base}"
    if len(candidate) > 64:
        suffix = hashlib.sha1(base.encode("utf-8")).hexdigest()[:8]
        candidate = f"off.{origin_site.lower()}.{base[:40]}-{suffix}"
    normalized = normalize_username(candidate)
    row = connection.execute("SELECT * FROM users WHERE username=?", (normalized,)).fetchone()
    if row:
        return dict(row)
    cursor = connection.execute(
        """INSERT INTO users(username,password_hash,display_name,status,password_changed_at,created_at,updated_at)
           VALUES(?,?,?,'disabled',?,?,?)""",
        (normalized, UNUSABLE_PASSWORD_HASH, f"{origin_site} 离线人员 {base}", now, now, now),
    )
    return dict(connection.execute("SELECT * FROM users WHERE id=?", (cursor.lastrowid,)).fetchone())


def _audit_context(principal: Principal, correlation_id: str) -> AuditContext:
    return AuditContext(
        actor_user_id=getattr(principal, "user_id", None),
        actor_name=str(getattr(principal, "display_name", "系统")),
        correlation_id=correlation_id,
    )


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------


class OfflineExportService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.packages = OfflinePackageRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def export(self, principal: Principal, since_package_code: str | None = None) -> dict[str, Any]:
        principal.require("offline_packages.manage")
        origin = site_id()
        parent = self.packages.latest(origin, direction="exported")
        if since_package_code:
            since = self.packages.by_code(origin, since_package_code)
            if since is None or since["direction"] != "exported":
                raise NotFoundError("指定的起始导出包不存在")
            watermark = self._package_watermark(since)
        elif parent:
            watermark = self._package_watermark(parent)
        else:
            watermark = {"intake_batches": 0, "dossiers": 0, "approval_requests": 0, "approval_decisions": 0, "dossier_events": 0}
        sequence = (parent["sequence"] if parent else 0) + 1
        now = to_storage(self.clock.now())
        items, warnings, next_watermark = self._gather(origin, watermark)
        document = build_package_document(
            package_code=f"{origin}-PKG-{sequence:06d}",
            origin_site=origin,
            sequence=sequence,
            parent_package_code=parent["package_code"] if parent else None,
            parent_digest=parent["package_digest"] if parent else None,
            created_at=now,
            items=items,
        )
        package = self.packages.create_package(
            package_code=document["package_code"],
            origin_site=origin,
            sequence=sequence,
            parent_package_code=document["parent_package_code"],
            parent_digest=document["parent_digest"],
            payload_digest=document["payload_digest"],
            package_digest=document["package_digest"],
            signature=document.get("signature"),
            direction="exported",
            status="exported",
            item_count=len(items),
            now=now,
        )
        for item in items:
            self.packages.add_item(
                package["id"],
                index=item["index"],
                item_type=item["type"],
                key=item["key"],
                payload=item["payload"],
                status="exported",
                now=now,
            )
        self.packages.save_result(package["id"], {"watermark": next_watermark})
        self.audit.record(
            principal,
            "offline.export",
            "offline_package",
            str(package["id"]),
            after={"package_code": package["package_code"], "item_count": len(items)},
            metadata={"origin_site": origin, "watermark": next_watermark},
        )
        return {**document, "package_id": package["id"], "warnings": warnings}

    def _package_watermark(self, package: dict[str, Any]) -> dict[str, int]:
        if not package["result_json"]:
            raise ValidationError(f"导出包 {package['package_code']} 缺少水位线信息，不能作为导出起点")
        watermark = json.loads(package["result_json"]).get("watermark")
        if not isinstance(watermark, dict):
            raise ValidationError(f"导出包 {package['package_code']} 缺少水位线信息，不能作为导出起点")
        return {key: int(watermark.get(key, 0)) for key in ("intake_batches", "dossiers", "approval_requests", "approval_decisions", "dossier_events")}

    def _max_id(self, table: str) -> int:
        return int(self.connection.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}").fetchone()[0])

    def _gather(self, origin: str, watermark: dict[str, int]) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
        warnings: list[str] = []
        ranked: list[tuple[int, int, dict[str, Any]]] = []
        batch_rows = self.connection.execute(
            """SELECT b.*,u.username AS received_by_username FROM intake_batches b
               LEFT JOIN users u ON u.id=b.received_by
               WHERE b.id > ? ORDER BY b.id""",
            (watermark["intake_batches"],),
        ).fetchall()
        for row in batch_rows:
            payload = {
                "intake_code": row["intake_code"],
                "project_code": row["project_code"],
                "expected_count": row["expected_count"],
                "received_by": row["received_by_username"] or "system",
                "occurred_at": row["created_at"],
            }
            ranked.append((0, row["id"], {
                "type": "intake_batch",
                "key": f"intake_batch:{row['intake_code']}",
                "payload": payload,
            }))
        dossier_rows = self.connection.execute(
            """SELECT s.*,b.intake_code,l.code AS vault_code,u.username AS custody_username
               FROM dossiers s JOIN intake_batches b ON b.id=s.intake_id
               LEFT JOIN vault_locations l ON l.id=s.vault_id
               LEFT JOIN users u ON u.id=s.custody_user_id
               WHERE s.id > ? ORDER BY s.id""",
            (watermark["dossiers"],),
        ).fetchall()
        for row in dossier_rows:
            payload = {
                "dossier_code": row["dossier_code"],
                "intake_code": row["intake_code"],
                "asset_type": row["asset_type"],
                "quantity": row["quantity"],
                "unit": row["unit"],
                "vault_code": row["vault_code"],
                "custody_user": row["custody_username"],
                "occurred_at": row["created_at"],
            }
            ranked.append((1, row["id"], {
                "type": "dossier_register",
                "key": f"dossier_register:{row['dossier_code']}",
                "payload": payload,
            }))
        changed_request_ids = {
            int(row[0])
            for row in self.connection.execute(
                "SELECT id FROM approval_requests WHERE id > ?", (watermark["approval_requests"],)
            ).fetchall()
        }
        changed_request_ids |= {
            int(row[0])
            for row in self.connection.execute(
                "SELECT DISTINCT request_id FROM approval_decisions WHERE id > ?",
                (watermark["approval_decisions"],),
            ).fetchall()
        }
        approval_rows = []
        if changed_request_ids:
            placeholders = ",".join("?" for _ in changed_request_ids)
            approval_rows = self.connection.execute(
                f"""SELECT r.*,u.username AS requested_by_username FROM approval_requests r
                    LEFT JOIN users u ON u.id=r.requested_by
                    WHERE r.id IN ({placeholders}) ORDER BY r.id""",
                tuple(sorted(changed_request_ids)),
            ).fetchall()
        for row in approval_rows:
            if row["resource_type"] != "dossier":
                warnings.append(f"审批 {row['request_code']} 的资源类型 {row['resource_type']} 不在离线同步范围，已跳过")
                continue
            dossier = self.connection.execute(
                "SELECT dossier_code FROM dossiers WHERE id=?", (row["resource_id"],)
            ).fetchone()
            if dossier is None:
                warnings.append(f"审批 {row['request_code']} 关联的档案不存在，已跳过")
                continue
            decisions = self.connection.execute(
                """SELECT d.decision,d.comment,d.decided_at,u.username AS approver
                   FROM approval_decisions d JOIN users u ON u.id=d.approver_user_id
                   WHERE d.request_id=? ORDER BY d.id""",
                (row["id"],),
            ).fetchall()
            payload = {
                "request_code": row["request_code"],
                "action_type": row["action_type"],
                "dossier_code": dossier["dossier_code"],
                "requested_by": row["requested_by_username"] or "system",
                "required_approvals": row["required_approvals"],
                "expires_at": row["expires_at"],
                "state": row["state"],
                "decisions": [dict(decision) for decision in decisions],
                "occurred_at": row["updated_at"],
            }
            ranked.append((2, row["id"], {
                "type": "approval_result",
                "key": f"approval_result:{row['request_code']}",
                "payload": payload,
            }))
        event_rows = self.connection.execute(
            """SELECT e.*,s.dossier_code FROM dossier_events e JOIN dossiers s ON s.id=e.dossier_id
               WHERE e.event_type='vault.transferred' AND e.id > ? ORDER BY e.id""",
            (watermark["dossier_events"],),
        ).fetchall()
        for row in event_rows:
            details = json.loads(row["details_json"])
            base_version = details.get("base_version")
            if base_version is None:
                warnings.append(f"档案 {row['dossier_code']} 的转移事件 {row['id']} 缺少前置版本，已跳过")
                continue
            vault = self.connection.execute(
                "SELECT code FROM vault_locations WHERE id=?", (details.get("to_vault_id"),)
            ).fetchone()
            if vault is None:
                warnings.append(f"档案 {row['dossier_code']} 的转移事件 {row['id']} 目标库位不存在，已跳过")
                continue
            payload = {
                "dossier_code": row["dossier_code"],
                "to_vault_code": vault["code"],
                "base_version": base_version,
                "transfer_code": details.get("transfer_code") or f"TRF-{origin}-{row['id']}",
                "reason": details.get("reason", ""),
                "occurred_at": row["occurred_at"],
            }
            ranked.append((3, row["id"], {
                "type": "vault_transfer",
                "key": f"vault_transfer:{payload['transfer_code']}",
                "payload": payload,
            }))
        ranked.sort(key=lambda entry: (entry[0], entry[1]))
        items = []
        for index, (_, _, item) in enumerate(ranked):
            items.append({"index": index, **item})
        next_watermark = {
            "intake_batches": self._max_id("intake_batches"),
            "dossiers": self._max_id("dossiers"),
            "approval_requests": self._max_id("approval_requests"),
            "approval_decisions": self._max_id("approval_decisions"),
            "dossier_events": self._max_id("dossier_events"),
        }
        return items, warnings, next_watermark


# ---------------------------------------------------------------------------
# 导入
# ---------------------------------------------------------------------------


class OfflineImportService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.packages = OfflinePackageRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # -- 预演 ---------------------------------------------------------------

    def preview(self, principal: Principal, document: Any) -> dict[str, Any]:
        """不落库地校验包并推演每个条目的处置方式，报告缺失依赖与分叉。"""
        principal.require("offline_packages.manage")
        report: dict[str, Any] = {
            "valid": True,
            "errors": [],
            "missing_dependencies": [],
            "forks": [],
            "items": [],
            "already_imported": False,
        }
        try:
            package = validate_package_document(document)
        except ValidationError as exc:
            report["valid"] = False
            report["errors"].append(exc.message)
            return report
        header = package["header"]
        report.update(
            {
                "package_code": header["package_code"],
                "origin_site": header["origin_site"],
                "sequence": header["sequence"],
                "package_digest": package["package_digest"],
            }
        )
        existing = self.packages.by_digest(package["package_digest"])
        if existing:
            report["already_imported"] = True
            report["existing_status"] = existing["status"]
            if existing["status"] == "committed" and existing["result_json"]:
                report["original_result"] = json.loads(existing["result_json"])
        clash = self.packages.by_code(header["origin_site"], header["package_code"])
        if clash and clash["package_digest"] != package["package_digest"]:
            report["errors"].append("同一来源已存在相同包编号但摘要不同的包")
        self._check_parent(header, report)
        simulation = {"intakes": set(), "dossiers": {}, "versions": {}, "transfers": set()}
        for item in package["items"]:
            report["items"].append(self._plan_item(header, item, simulation, report))
        report["valid"] = not report["errors"] and not report["missing_dependencies"]
        return report

    def _check_parent(self, header: dict[str, Any], report: dict[str, Any]) -> None:
        origin = header["origin_site"]
        if header["parent_package_code"]:
            parent = self.packages.by_code(origin, header["parent_package_code"])
            if parent is None or parent["package_digest"] != header["parent_digest"]:
                report["missing_dependencies"].append(
                    {
                        "kind": "parent_package",
                        "package_code": header["parent_package_code"],
                        "detail": f"父包 {header['parent_package_code']} 尚未导入",
                    }
                )
                return
            if parent["direction"] == "imported" and parent["status"] != "committed":
                report["missing_dependencies"].append(
                    {
                        "kind": "parent_package",
                        "package_code": header["parent_package_code"],
                        "detail": f"父包 {header['parent_package_code']} 已登记但尚未提交完成（当前状态 {parent['status']}）",
                    }
                )
            if header["sequence"] != parent["sequence"] + 1:
                report["errors"].append("包序号必须等于父包序号加一")
        else:
            if header["sequence"] != 1:
                report["errors"].append("无父包指针的首包序号必须为 1")
            if self.packages.latest(origin, direction="imported", status="committed"):
                report["errors"].append("该来源已存在已提交的包，首包不能没有父包指针")

    def _plan_item(
        self,
        header: dict[str, Any],
        item: dict[str, Any],
        simulation: dict[str, Any],
        report: dict[str, Any],
    ) -> dict[str, Any]:
        plan = {"index": item["index"], "type": item["type"], "key": item["key"], "action": "apply", "detail": ""}
        payload = item["payload"]
        try:
            if item["type"] == "intake_batch":
                self._plan_intake_batch(payload, plan, simulation)
            elif item["type"] == "dossier_register":
                self._plan_dossier_register(header, payload, plan, simulation, report)
            elif item["type"] == "vault_transfer":
                self._plan_vault_transfer(payload, plan, simulation, report)
            elif item["type"] == "approval_result":
                self._plan_approval_result(header, payload, plan, simulation, report)
        except MissingDependencyError as exc:
            plan["action"] = "blocked"
            plan["detail"] = str(exc)
            report["missing_dependencies"].extend(exc.dependencies)
        if plan["action"] == "error":
            report["errors"].append(f"条目 {item['index']}（{item['key']}）：{plan['detail']}")
        return plan

    def _plan_intake_batch(self, payload: dict[str, Any], plan: dict[str, Any], simulation: dict[str, Any]) -> None:
        existing = self._intake_by_code(payload["intake_code"])
        if existing:
            if existing["project_code"] != payload["project_code"]:
                plan["action"] = "error"
                plan["detail"] = "移交批次编号已存在但项目编号不一致"
                return
            plan["action"] = "skip"
            plan["detail"] = "移交批次已存在"
        simulation["intakes"].add(payload["intake_code"])

    def _plan_dossier_register(
        self,
        header: dict[str, Any],
        payload: dict[str, Any],
        plan: dict[str, Any],
        simulation: dict[str, Any],
        report: dict[str, Any],
    ) -> None:
        dependencies = []
        if payload["intake_code"] not in simulation["intakes"] and not self._intake_by_code(payload["intake_code"]):
            dependencies.append(
                {
                    "kind": "intake_batch",
                    "code": payload["intake_code"],
                    "detail": f"档案 {payload['dossier_code']} 引用的移交批次 {payload['intake_code']} 尚未到达",
                }
            )
        if payload.get("vault_code") and not self._vault_by_code(payload["vault_code"]):
            dependencies.append(
                {
                    "kind": "vault",
                    "code": payload["vault_code"],
                    "detail": f"档案 {payload['dossier_code']} 引用的库位 {payload['vault_code']} 不存在",
                }
            )
        if dependencies:
            raise MissingDependencyError(dependencies)
        existing = self._dossier_by_code(payload["dossier_code"])
        if existing:
            if self._register_fingerprint(existing) == self._register_fingerprint(payload):
                plan["action"] = "skip"
                plan["detail"] = "档案已存在且内容一致"
            else:
                plan["action"] = "conflict"
                plan["detail"] = "档案已存在但登记内容不一致，将进入人工裁决"
                report["forks"].append({"dossier_code": payload["dossier_code"], "reason": "register_conflict"})
            simulation["versions"][payload["dossier_code"]] = existing["version"]
            return
        simulation["dossiers"][payload["dossier_code"]] = payload
        simulation["versions"][payload["dossier_code"]] = 1

    def _plan_vault_transfer(
        self,
        payload: dict[str, Any],
        plan: dict[str, Any],
        simulation: dict[str, Any],
        report: dict[str, Any],
    ) -> None:
        dossier = self._dossier_by_code(payload["dossier_code"])
        dependencies = []
        if dossier is None and payload["dossier_code"] not in simulation["dossiers"]:
            dependencies.append(
                {
                    "kind": "dossier",
                    "code": payload["dossier_code"],
                    "detail": f"载体变更引用的档案 {payload['dossier_code']} 尚未到达",
                }
            )
        if not self._vault_by_code(payload["to_vault_code"]):
            dependencies.append(
                {
                    "kind": "vault",
                    "code": payload["to_vault_code"],
                    "detail": f"载体变更目标库位 {payload['to_vault_code']} 不存在",
                }
            )
        if dependencies:
            raise MissingDependencyError(dependencies)
        if dossier and self._transfer_applied(dossier["id"], payload["transfer_code"]):
            plan["action"] = "skip"
            plan["detail"] = "该载体变更已应用"
            simulation["versions"][payload["dossier_code"]] = dossier["version"]
            return
        current_version = simulation["versions"].get(payload["dossier_code"])
        if current_version is None:
            current_version = dossier["version"] if dossier else 1
        base_version = payload["base_version"]
        if current_version == base_version:
            plan["detail"] = f"基于版本 {base_version} 应用载体变更"
            simulation["versions"][payload["dossier_code"]] = current_version + 1
        elif current_version < base_version:
            raise MissingDependencyError(
                [
                    {
                        "kind": "base_version",
                        "dossier_code": payload["dossier_code"],
                        "base_version": base_version,
                        "local_version": current_version,
                        "detail": (
                            f"档案 {payload['dossier_code']} 的载体变更基于版本 {base_version}，"
                            f"本地当前版本 {current_version}，前置版本尚未到达"
                        ),
                    }
                ]
            )
        else:
            plan["action"] = "conflict"
            plan["detail"] = (
                f"档案 {payload['dossier_code']} 本地版本 {current_version} 与变更基准版本 {base_version} 分叉，将进入人工裁决"
            )
            report["forks"].append(
                {
                    "dossier_code": payload["dossier_code"],
                    "reason": "version_fork",
                    "local_version": current_version,
                    "base_version": base_version,
                }
            )

    def _plan_approval_result(
        self,
        header: dict[str, Any],
        payload: dict[str, Any],
        plan: dict[str, Any],
        simulation: dict[str, Any],
        report: dict[str, Any],
    ) -> None:
        if not self._dossier_by_code(payload["dossier_code"]) and payload["dossier_code"] not in simulation["dossiers"]:
            raise MissingDependencyError(
                [
                    {
                        "kind": "dossier",
                        "code": payload["dossier_code"],
                        "detail": f"审批结果引用的档案 {payload['dossier_code']} 尚未到达",
                    }
                ]
            )
        request = self._approval_by_code(payload["request_code"])
        if request is None:
            plan["detail"] = "登记审批请求并写入审批决定"
            return
        if request["action_type"] != payload["action_type"]:
            plan["action"] = "conflict"
            plan["detail"] = "审批请求已存在但类型不一致，将进入人工裁决"
            report["forks"].append({"dossier_code": payload["dossier_code"], "reason": "approval_conflict"})
            return
        origin = header["origin_site"]
        existing = {
            row["approver_user_id"]: row
            for row in self.connection.execute(
                "SELECT * FROM approval_decisions WHERE request_id=?", (request["id"],)
            ).fetchall()
        }
        new_decisions = 0
        for decision in payload["decisions"]:
            approver = self.connection.execute(
                "SELECT id FROM users WHERE username=?",
                (self._shadow_username(origin, decision["approver"]),),
            ).fetchone()
            if approver and approver["id"] in existing:
                continue
            new_decisions += 1
        if new_decisions == 0 and request["state"] == self._approval_state(request["required_approvals"], list(existing.values())):
            plan["action"] = "skip"
            plan["detail"] = "审批结果已同步"
        else:
            plan["detail"] = f"补充 {new_decisions} 条审批决定"

    # -- 导入入口 -----------------------------------------------------------

    def import_package(self, principal: Principal, document: Any) -> dict[str, Any]:
        """登记并提交离线包；同一包重复提交返回原批次结果，不重复写入。"""
        principal.require("offline_packages.manage")
        package = validate_package_document(document)
        header = package["header"]
        existing = self.packages.by_digest(package["package_digest"])
        if existing:
            if existing["status"] == "committed":
                result = json.loads(existing["result_json"]) if existing["result_json"] else self._build_result(existing)
                return {**result, "replayed": True}
            return self.commit(principal, existing["id"])
        clash = self.packages.by_code(header["origin_site"], header["package_code"])
        if clash:
            raise ConflictError("同一来源已存在相同包编号但摘要不同的包")
        now = to_storage(self.clock.now())
        try:
            with transaction(immediate=True):
                staged = self.packages.create_package(
                    package_code=header["package_code"],
                    origin_site=header["origin_site"],
                    sequence=header["sequence"],
                    parent_package_code=header["parent_package_code"],
                    parent_digest=header["parent_digest"],
                    payload_digest=package["payload_digest"],
                    package_digest=package["package_digest"],
                    signature=package["signature"],
                    direction="imported",
                    status="staged",
                    item_count=len(package["items"]),
                    now=now,
                )
                for item in package["items"]:
                    self.packages.add_item(
                        staged["id"],
                        index=item["index"],
                        item_type=item["type"],
                        key=item["key"],
                        payload=item["payload"],
                        status="pending",
                        now=now,
                    )
                self.audit.record(
                    _audit_context(principal, header["package_code"]),
                    "offline.import.staged",
                    "offline_package",
                    str(staged["id"]),
                    after={"package_code": header["package_code"], "item_count": len(package["items"])},
                )
        except sqlite3.IntegrityError:
            # 并发重传：另一请求已登记同一包，直接返回该包的批次结果
            raced = self.packages.by_digest(package["package_digest"])
            if raced is None:
                raise
            if raced["status"] == "committed":
                result = json.loads(raced["result_json"]) if raced["result_json"] else self._build_result(raced)
                return {**result, "replayed": True}
            return self.commit(principal, raced["id"])
        return self.commit(principal, staged["id"])

    def commit(self, principal: Principal, package_id: int) -> dict[str, Any]:
        """分阶段提交：父包闸门 → 逐条事务应用 → 汇总结果；失败后可再次调用继续。"""
        principal.require("offline_packages.manage")
        package = self.packages.get(package_id)
        if package["direction"] != "imported":
            raise ValidationError("只有导入方向的离线包需要提交")
        if package["status"] == "committed":
            result = json.loads(package["result_json"]) if package["result_json"] else self._build_result(package)
            return {**result, "replayed": True}
        resumed = package["status"] == "failed"
        dependency_failure = self._parent_gate(package)
        if dependency_failure:
            with transaction(immediate=True):
                self.packages.update_status(
                    package_id, "failed", to_storage(self.clock.now()),
                    error_message=dependency_failure[0]["detail"],
                )
                result = self._build_result(self.packages.get(package_id), missing_dependencies=dependency_failure)
                self.packages.save_result(package_id, result)
            return {**result, "resumed": resumed}
        for item in self.packages.pending_items(package_id):
            now = to_storage(self.clock.now())
            try:
                with transaction(immediate=True):
                    outcome = self._apply_item(package, item, principal, now)
                    self.packages.update_item(
                        item["id"],
                        outcome["status"],
                        now,
                        resource_type=outcome.get("resource_type"),
                        resource_id=outcome.get("resource_id"),
                        error_message=outcome.get("error_message"),
                    )
            except MissingDependencyError as exc:
                with transaction(immediate=True):
                    self.packages.update_item(item["id"], "failed", now, error_message=str(exc))
                    self.packages.update_status(package_id, "failed", now, error_message=str(exc))
                    result = self._build_result(self.packages.get(package_id), missing_dependencies=exc.dependencies)
                    self.packages.save_result(package_id, result)
                return {**result, "resumed": resumed}
            except Exception as exc:  # 领域校验等失败：记录失败状态，之后可断点续传
                with transaction(immediate=True):
                    self.packages.update_item(item["id"], "failed", now, error_message=str(exc))
                    self.packages.update_status(package_id, "failed", now, error_message=str(exc))
                    result = self._build_result(self.packages.get(package_id))
                    self.packages.save_result(package_id, result)
                return {**result, "resumed": resumed}
        now = to_storage(self.clock.now())
        with transaction(immediate=True):
            self.packages.update_status(package_id, "committed", now, committed_at=now)
            finalized = self.packages.get(package_id)
            result = self._build_result(finalized)
            self.packages.save_result(package_id, result)
            self.audit.record(
                _audit_context(principal, finalized["package_code"]),
                "offline.import.committed",
                "offline_package",
                str(package_id),
                after={"status": "committed", "applied": result["applied"], "conflicts": len(result["conflicts"])},
            )
        return {**result, "resumed": resumed}

    def _parent_gate(self, package: dict[str, Any]) -> list[dict[str, Any]] | None:
        if not package["parent_package_code"]:
            if package["sequence"] != 1:
                return [
                    {
                        "kind": "sequence",
                        "detail": f"首包序号必须为 1，实际为 {package['sequence']}",
                    }
                ]
            if self.packages.latest(package["origin_site"], direction="imported", status="committed"):
                return [
                    {
                        "kind": "sequence",
                        "detail": "该来源已存在已提交的首包，无父包指针的包不能提交",
                    }
                ]
            return None
        parent = self.packages.by_code(package["origin_site"], package["parent_package_code"])
        if parent is None or parent["package_digest"] != package["parent_digest"]:
            return [
                {
                    "kind": "parent_package",
                    "package_code": package["parent_package_code"],
                    "detail": f"父包 {package['parent_package_code']} 尚未导入",
                }
            ]
        if parent["direction"] == "imported" and parent["status"] != "committed":
            return [
                {
                    "kind": "parent_package",
                    "package_code": package["parent_package_code"],
                    "detail": f"父包 {package['parent_package_code']} 尚未提交完成（当前状态 {parent['status']}）",
                }
            ]
        if package["sequence"] != parent["sequence"] + 1:
            return [
                {
                    "kind": "sequence",
                    "detail": f"包序号 {package['sequence']} 与父包序号 {parent['sequence']} 不连续",
                }
            ]
        return None

    # -- 条目应用 -----------------------------------------------------------

    def _apply_item(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        handler = {
            "intake_batch": self._apply_intake_batch,
            "dossier_register": self._apply_dossier_register,
            "approval_result": self._apply_approval_result,
            "vault_transfer": self._apply_vault_transfer,
        }[item["item_type"]]
        outcome = handler(package, item, item["payload"], principal, now)
        self.audit.record(
            _audit_context(principal, package["package_code"]),
            f"offline.import.{item['item_type']}",
            outcome.get("resource_type") or item["item_type"],
            outcome.get("resource_id"),
            metadata={
                "package_code": package["package_code"],
                "item_index": item["item_index"],
                "item_key": item["item_key"],
                "status": outcome["status"],
            },
        )
        return outcome

    def _apply_intake_batch(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        payload: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        existing = self._intake_by_code(payload["intake_code"])
        if existing:
            if existing["project_code"] != payload["project_code"]:
                raise ConflictError(f"移交批次 {payload['intake_code']} 已存在但项目编号不一致")
            return {"status": "skipped", "resource_type": "intake_batch", "resource_id": existing["id"]}
        receiver = ensure_shadow_user(self.connection, package["origin_site"], payload["received_by"], now)
        cursor = self.connection.execute(
            """INSERT INTO intake_batches(intake_code,project_code,received_by,received_at,expected_count,status,qr_payload,created_at,updated_at)
               VALUES(?,?,?,?,?,'open',?,?,?)""",
            (
                payload["intake_code"],
                payload["project_code"],
                receiver["id"],
                payload["occurred_at"],
                payload["expected_count"],
                f"offline-intake:{package['origin_site']}:{payload['intake_code']}",
                now,
                now,
            ),
        )
        return {"status": "applied", "resource_type": "intake_batch", "resource_id": cursor.lastrowid}

    def _apply_dossier_register(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        payload: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        intake = self._intake_by_code(payload["intake_code"])
        dependencies = []
        if intake is None:
            dependencies.append(
                {
                    "kind": "intake_batch",
                    "code": payload["intake_code"],
                    "detail": f"档案 {payload['dossier_code']} 引用的移交批次 {payload['intake_code']} 尚未到达",
                }
            )
        vault = self._vault_by_code(payload["vault_code"]) if payload.get("vault_code") else None
        if payload.get("vault_code") and vault is None:
            dependencies.append(
                {
                    "kind": "vault",
                    "code": payload["vault_code"],
                    "detail": f"档案 {payload['dossier_code']} 引用的库位 {payload['vault_code']} 不存在",
                }
            )
        if dependencies:
            raise MissingDependencyError(dependencies)
        existing = self._dossier_by_code(payload["dossier_code"])
        if existing:
            if self._register_fingerprint(existing) == self._register_fingerprint(payload):
                return {"status": "skipped", "resource_type": "dossier", "resource_id": existing["id"]}
            fork = self.packages.create_fork(
                dossier_id=existing["id"],
                package_id=package["id"],
                item_id=item["id"],
                reason="register_conflict",
                local_snapshot=self._dossier_snapshot(existing),
                incoming_payload=payload,
                now=now,
            )
            return {
                "status": "conflict",
                "resource_type": "dossier",
                "resource_id": existing["id"],
                "error_message": f"档案登记内容分叉，已创建人工裁决 {fork['fork_code']}",
                "fork_code": fork["fork_code"],
            }
        custody = None
        if payload.get("custody_user"):
            custody = ensure_shadow_user(self.connection, package["origin_site"], payload["custody_user"], now)
        dossier = self.dossiers.create(
            {
                "dossier_code": payload["dossier_code"],
                "intake_id": intake["id"],
                "asset_type": payload["asset_type"],
                "quantity": payload["quantity"],
                "unit": payload["unit"],
                "lifecycle_state": "available",
                "vault_id": vault["id"] if vault else None,
                "custody_user_id": custody["id"] if custody else None,
                "provenance_depth": 0,
            },
            now,
        )
        self.dossiers.append_event(
            dossier["id"],
            "received",
            custody["id"] if custody else None,
            now,
            to_state="available",
            details={
                "intake_code": payload["intake_code"],
                "offline": True,
                "origin_site": package["origin_site"],
                "occurred_at": payload["occurred_at"],
            },
            correlation_id=package["package_code"],
        )
        self.connection.execute(
            "UPDATE intake_batches SET accepted_count=(SELECT COUNT(*) FROM dossiers WHERE intake_id=?),updated_at=? WHERE id=?",
            (intake["id"], now, intake["id"]),
        )
        return {"status": "applied", "resource_type": "dossier", "resource_id": dossier["id"]}

    def _apply_vault_transfer(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        payload: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        dossier = self._dossier_by_code(payload["dossier_code"])
        dependencies = []
        if dossier is None:
            dependencies.append(
                {
                    "kind": "dossier",
                    "code": payload["dossier_code"],
                    "detail": f"载体变更引用的档案 {payload['dossier_code']} 尚未到达",
                }
            )
        vault = self._vault_by_code(payload["to_vault_code"])
        if vault is None:
            dependencies.append(
                {
                    "kind": "vault",
                    "code": payload["to_vault_code"],
                    "detail": f"载体变更目标库位 {payload['to_vault_code']} 不存在",
                }
            )
        if dependencies:
            raise MissingDependencyError(dependencies)
        if self._transfer_applied(dossier["id"], payload["transfer_code"]):
            return {"status": "skipped", "resource_type": "dossier", "resource_id": dossier["id"]}
        base_version = payload["base_version"]
        if dossier["version"] < base_version:
            raise MissingDependencyError(
                [
                    {
                        "kind": "base_version",
                        "dossier_code": payload["dossier_code"],
                        "base_version": base_version,
                        "local_version": dossier["version"],
                        "detail": (
                            f"档案 {payload['dossier_code']} 的载体变更基于版本 {base_version}，"
                            f"本地当前版本 {dossier['version']}，前置版本尚未到达"
                        ),
                    }
                ]
            )
        if dossier["version"] > base_version:
            fork = self.packages.create_fork(
                dossier_id=dossier["id"],
                package_id=package["id"],
                item_id=item["id"],
                reason="version_fork",
                local_snapshot=self._dossier_snapshot(dossier),
                incoming_payload=payload,
                now=now,
            )
            return {
                "status": "conflict",
                "resource_type": "dossier",
                "resource_id": dossier["id"],
                "error_message": (
                    f"本地版本 {dossier['version']} 与变更基准版本 {base_version} 分叉，已创建人工裁决 {fork['fork_code']}"
                ),
                "fork_code": fork["fork_code"],
            }
        operator = ensure_shadow_user(self.connection, package["origin_site"], "transfer-agent", now)
        updated = self.connection.execute(
            "UPDATE dossiers SET vault_id=?,custody_user_id=?,version=version+1,updated_at=? WHERE id=? AND version=?",
            (vault["id"], operator["id"], now, dossier["id"], base_version),
        )
        if updated.rowcount != 1:
            raise ConflictError("档案版本在应用载体变更时发生变化，请重试")
        self.dossiers.append_event(
            dossier["id"],
            "vault.transferred",
            operator["id"],
            now,
            details={
                "from_vault_id": dossier["vault_id"],
                "to_vault_id": vault["id"],
                "reason": payload["reason"],
                "base_version": base_version,
                "transfer_code": payload["transfer_code"],
                "offline": True,
                "origin_site": package["origin_site"],
            },
            correlation_id=package["package_code"],
        )
        return {"status": "applied", "resource_type": "dossier", "resource_id": dossier["id"]}

    def _apply_approval_result(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        payload: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        dossier = self._dossier_by_code(payload["dossier_code"])
        if dossier is None:
            raise MissingDependencyError(
                [
                    {
                        "kind": "dossier",
                        "code": payload["dossier_code"],
                        "detail": f"审批结果引用的档案 {payload['dossier_code']} 尚未到达",
                    }
                ]
            )
        request = self._approval_by_code(payload["request_code"])
        changed = False
        if request is None:
            requester = ensure_shadow_user(self.connection, package["origin_site"], payload["requested_by"], now)
            cursor = self.connection.execute(
                """INSERT INTO approval_requests(request_code,action_type,resource_type,resource_id,requested_by,
                   payload_json,state,required_approvals,expires_at,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,'pending',?,?,?,?)""",
                (
                    payload["request_code"],
                    payload["action_type"],
                    "dossier",
                    dossier["id"],
                    requester["id"],
                    canonical_json({"offline_origin": package["origin_site"]}),
                    payload["required_approvals"],
                    payload["expires_at"],
                    now,
                    now,
                ),
            )
            request = self._approval_by_id(cursor.lastrowid)
            changed = True
        elif request["action_type"] != payload["action_type"] or request["resource_id"] != dossier["id"]:
            fork = self.packages.create_fork(
                dossier_id=dossier["id"],
                package_id=package["id"],
                item_id=item["id"],
                reason="approval_conflict",
                local_snapshot=request,
                incoming_payload=payload,
                now=now,
            )
            return {
                "status": "conflict",
                "resource_type": "approval_request",
                "resource_id": request["id"],
                "error_message": f"审批请求内容分叉，已创建人工裁决 {fork['fork_code']}",
                "fork_code": fork["fork_code"],
            }
        for decision in payload["decisions"]:
            approver = ensure_shadow_user(self.connection, package["origin_site"], decision["approver"], now)
            existing = self.connection.execute(
                "SELECT * FROM approval_decisions WHERE request_id=? AND approver_user_id=?",
                (request["id"], approver["id"]),
            ).fetchone()
            if existing:
                if existing["decision"] != decision["decision"]:
                    fork = self.packages.create_fork(
                        dossier_id=dossier["id"],
                        package_id=package["id"],
                        item_id=item["id"],
                        reason="approval_conflict",
                        local_snapshot=self._approval_snapshot(request),
                        incoming_payload=payload,
                        now=now,
                    )
                    return {
                        "status": "conflict",
                        "resource_type": "approval_request",
                        "resource_id": request["id"],
                        "error_message": f"审批决定分叉，已创建人工裁决 {fork['fork_code']}",
                        "fork_code": fork["fork_code"],
                    }
                continue
            self.connection.execute(
                "INSERT INTO approval_decisions(request_id,approver_user_id,decision,comment,decided_at) VALUES(?,?,?,?,?)",
                (request["id"], approver["id"], decision["decision"], decision.get("comment", ""), decision["decided_at"]),
            )
            changed = True
        decisions = self.connection.execute(
            "SELECT * FROM approval_decisions WHERE request_id=?", (request["id"],)
        ).fetchall()
        target_state = self._approval_state(request["required_approvals"], decisions)
        if target_state != request["state"]:
            if request["state"] != "pending":
                fork = self.packages.create_fork(
                    dossier_id=dossier["id"],
                    package_id=package["id"],
                    item_id=item["id"],
                    reason="approval_conflict",
                    local_snapshot=self._approval_snapshot(request),
                    incoming_payload=payload,
                    now=now,
                )
                return {
                    "status": "conflict",
                    "resource_type": "approval_request",
                    "resource_id": request["id"],
                    "error_message": (
                        f"审批请求已处于 {request['state']} 状态，远端决定会改变结论，已创建人工裁决 {fork['fork_code']}"
                    ),
                    "fork_code": fork["fork_code"],
                }
            self.connection.execute(
                "UPDATE approval_requests SET state=?,version=version+1,updated_at=? WHERE id=?",
                (target_state, now, request["id"]),
            )
            changed = True
        return {
            "status": "applied" if changed else "skipped",
            "resource_type": "approval_request",
            "resource_id": request["id"],
        }

    # -- 结果汇总 -----------------------------------------------------------

    def _build_result(
        self,
        package: dict[str, Any],
        *,
        missing_dependencies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        items = self.packages.items(package["id"])
        forks = self.packages.list_forks(package_id=package["id"])
        conflicts = [
            {"item_key": item["item_key"], "dossier_id": fork["dossier_id"], "fork_code": fork["fork_code"], "reason": fork["reason"]}
            for item in items
            for fork in forks
            if fork["item_id"] == item["id"]
        ]
        return {
            "package_id": package["id"],
            "package_code": package["package_code"],
            "origin_site": package["origin_site"],
            "sequence": package["sequence"],
            "package_digest": package["package_digest"],
            "status": package["status"],
            "applied": sum(1 for item in items if item["status"] == "applied"),
            "skipped": sum(1 for item in items if item["status"] == "skipped"),
            "failed": sum(1 for item in items if item["status"] == "failed"),
            "conflicts": conflicts,
            "missing_dependencies": missing_dependencies or [],
            "error_message": package["error_message"],
            "items": [
                {
                    "index": item["item_index"],
                    "type": item["item_type"],
                    "key": item["item_key"],
                    "status": item["status"],
                    "resource_type": item["resource_type"],
                    "resource_id": item["resource_id"],
                    "error_message": item["error_message"],
                }
                for item in items
            ],
            "committed_at": package["committed_at"],
        }

    # -- 查询小工具 -----------------------------------------------------------

    def _shadow_username(self, origin_site: str, username: str) -> str:
        base = normalize_username(username)
        candidate = f"off.{origin_site.lower()}.{base}"
        if len(candidate) > 64:
            suffix = hashlib.sha1(base.encode("utf-8")).hexdigest()[:8]
            candidate = f"off.{origin_site.lower()}.{base[:40]}-{suffix}"
        return candidate

    def _intake_by_code(self, intake_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM intake_batches WHERE intake_code=?", (intake_code,)
        ).fetchone()
        return dict(row) if row else None

    def _vault_by_code(self, vault_code: str | None) -> dict[str, Any] | None:
        if not vault_code:
            return None
        row = self.connection.execute("SELECT * FROM vault_locations WHERE code=?", (vault_code,)).fetchone()
        return dict(row) if row else None

    def _dossier_by_code(self, dossier_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT s.*,b.intake_code,l.code AS vault_code FROM dossiers s
               JOIN intake_batches b ON b.id=s.intake_id
               LEFT JOIN vault_locations l ON l.id=s.vault_id WHERE s.dossier_code=?""",
            (dossier_code,),
        ).fetchone()
        return dict(row) if row else None

    def _approval_by_code(self, request_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM approval_requests WHERE request_code=?", (request_code,)
        ).fetchone()
        return dict(row) if row else None

    def _approval_by_id(self, request_id: int) -> dict[str, Any]:
        return dict(self.connection.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone())

    def _approval_state(self, required_approvals: int, decisions: list[Any]) -> str:
        values = [row["decision"] for row in decisions]
        if "reject" in values:
            return "rejected"
        if len(values) >= required_approvals:
            return "approved"
        return "pending"

    def _approval_snapshot(self, request: dict[str, Any]) -> dict[str, Any]:
        decisions = self.connection.execute(
            "SELECT * FROM approval_decisions WHERE request_id=? ORDER BY id", (request["id"],)
        ).fetchall()
        return {**request, "decisions": [dict(row) for row in decisions]}

    def _dossier_snapshot(self, dossier: dict[str, Any]) -> dict[str, Any]:
        return {
            key: dossier.get(key)
            for key in (
                "id", "dossier_code", "intake_code", "asset_type", "quantity", "reserved_quantity",
                "unit", "lifecycle_state", "vault_id", "vault_code", "version",
            )
        }

    def _register_fingerprint(self, data: dict[str, Any]) -> tuple:
        return (
            data.get("intake_code"),
            data.get("asset_type"),
            round(float(data.get("quantity") or 0), 9),
            data.get("unit"),
            data.get("vault_code"),
        )

    def _transfer_applied(self, dossier_id: int, transfer_code: str) -> bool:
        rows = self.connection.execute(
            "SELECT details_json FROM dossier_events WHERE dossier_id=? AND event_type='vault.transferred'",
            (dossier_id,),
        ).fetchall()
        for row in rows:
            if json.loads(row["details_json"]).get("transfer_code") == transfer_code:
                return True
        return False


# ---------------------------------------------------------------------------
# 分叉裁决
# ---------------------------------------------------------------------------


class OfflineForkService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.packages = OfflinePackageRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("offline_packages.read")
        return self.packages.list_forks(state=state)

    def resolve(self, principal: Principal, fork_id: int, resolution: str, note: str) -> dict[str, Any]:
        """人工裁决：保留本地（keep_local）或采用远端（apply_remote）；两条来源都保留在分叉记录中。"""
        principal.require("offline_packages.adjudicate")
        fork = self.packages.get_fork(fork_id)
        if fork["state"] != "pending":
            raise ConflictError("该分叉已经完成人工裁决")
        now = to_storage(self.clock.now())
        package = self.packages.get(fork["package_id"])
        item = next(entry for entry in self.packages.items(package["id"]) if entry["id"] == fork["item_id"])
        if resolution == "keep_local":
            resolved = self.packages.resolve_fork(fork_id, "resolved_local", note, getattr(principal, "user_id", None), now)
        else:
            self._apply_remote(package, item, fork, principal, now)
            self.packages.update_item(item["id"], "applied", now)
            resolved = self.packages.resolve_fork(fork_id, "resolved_remote", note, getattr(principal, "user_id", None), now)
        self.audit.record(
            _audit_context(principal, package["package_code"]),
            "offline.fork.resolve",
            "dossier_fork",
            str(fork_id),
            before=fork,
            after=resolved,
            metadata={"resolution": resolution, "package_code": package["package_code"]},
        )
        return resolved

    def _apply_remote(
        self,
        package: dict[str, Any],
        item: dict[str, Any],
        fork: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> None:
        payload = fork["incoming_payload"]
        dossier = self.dossiers.get(fork["dossier_id"])
        if item["item_type"] == "vault_transfer":
            vault_row = self.connection.execute(
                "SELECT * FROM vault_locations WHERE code=?", (payload["to_vault_code"],)
            ).fetchone()
            if vault_row is None:
                raise ValidationError(f"目标库位 {payload['to_vault_code']} 不存在，无法采用远端变更")
            vault = dict(vault_row)
            if dossier["vault_id"] != vault["id"]:
                self.connection.execute(
                    "UPDATE dossiers SET vault_id=?,version=version+1,updated_at=? WHERE id=?",
                    (vault["id"], now, dossier["id"]),
                )
            self.dossiers.append_event(
                dossier["id"],
                "vault.transferred",
                getattr(principal, "user_id", None),
                now,
                details={
                    "from_vault_id": dossier["vault_id"],
                    "to_vault_id": vault["id"],
                    "reason": payload["reason"],
                    "base_version": dossier["version"],
                    "transfer_code": payload["transfer_code"],
                    "fork_code": fork["fork_code"],
                    "forced": True,
                    "offline": True,
                    "origin_site": package["origin_site"],
                },
                correlation_id=package["package_code"],
            )
        elif item["item_type"] == "dossier_register":
            vault_id = dossier["vault_id"]
            if payload.get("vault_code"):
                vault_row = self.connection.execute(
                    "SELECT id FROM vault_locations WHERE code=?", (payload["vault_code"],)
                ).fetchone()
                if vault_row is None:
                    raise ValidationError(f"库位 {payload['vault_code']} 不存在，无法采用远端登记内容")
                vault_id = vault_row["id"]
            if payload["quantity"] < dossier["reserved_quantity"]:
                raise ConflictError("远端登记数量小于本地已预留数量，无法采用远端内容")
            self.connection.execute(
                """UPDATE dossiers SET asset_type=?,quantity=?,unit=?,vault_id=?,version=version+1,updated_at=?
                   WHERE id=?""",
                (payload["asset_type"], payload["quantity"], payload["unit"], vault_id, now, dossier["id"]),
            )
            self.dossiers.append_event(
                dossier["id"],
                "fork.resolved",
                getattr(principal, "user_id", None),
                now,
                details={
                    "fork_code": fork["fork_code"],
                    "resolution": "apply_remote",
                    "before": fork["local_snapshot"],
                    "after": payload,
                },
                correlation_id=package["package_code"],
            )
        elif item["item_type"] == "approval_result":
            importer = OfflineImportService(self.connection, self.clock)
            outcome = importer._apply_approval_result(package, item, payload, principal, now)
            if outcome["status"] == "conflict":
                raise ConflictError("远端审批结果与本地仍存在冲突，无法采用")
        else:  # pragma: no cover - 分叉只可能来自上述三类条目
            raise ValidationError(f"条目类型 {item['item_type']} 不支持远端裁决")


# ---------------------------------------------------------------------------
# 独立核对
# ---------------------------------------------------------------------------


class OfflineVerificationService:
    """导入完成后的独立核对：摘要链、顺序、审计链、版本关系与当前有效状态。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.packages = OfflinePackageRepository(connection)

    def verify(self, principal: Principal, package_id: int) -> dict[str, Any]:
        principal.require("offline_packages.read")
        package = self.packages.get(package_id)
        return self._verify_package(package)

    def verify_by_code(self, principal: Principal, package_code: str) -> dict[str, Any]:
        principal.require("offline_packages.read")
        matches = self.packages.find_by_code(package_code)
        if not matches:
            raise NotFoundError("离线包不存在")
        if len(matches) > 1:
            raise ValidationError("包编号对应多个来源的离线包，请使用包 ID 核对")
        return self._verify_package(matches[0])

    def _verify_package(self, package: dict[str, Any]) -> dict[str, Any]:
        checks = [
            self._check_digests(package),
            self._check_signature(package),
            self._check_parent_chain(package),
        ]
        if package["direction"] == "imported":
            checks.append(self._check_sequence(package))
            checks.append(self._check_items_consistent(package))
            checks.append(self._check_audit_trail(package))
            checks.append(self._check_effective_state(package))
            checks.append(self._check_forks(package))
        return {
            "package_id": package["id"],
            "package_code": package["package_code"],
            "origin_site": package["origin_site"],
            "sequence": package["sequence"],
            "direction": package["direction"],
            "status": package["status"],
            "ok": all(check["ok"] for check in checks),
            "checks": checks,
            "verified_at": to_storage(self.clock.now()),
        }

    def _check_digests(self, package: dict[str, Any]) -> dict[str, Any]:
        items = self.packages.items(package["id"])
        problems = []
        document_items = []
        for item in items:
            entry = {
                "index": item["item_index"],
                "type": item["item_type"],
                "key": item["item_key"],
                "payload": item["payload"],
            }
            if item_digest(entry) != item["payload_digest"]:
                problems.append(f"条目 {item['item_index']} 摘要不一致")
            document_items.append(entry)
        if compute_payload_digest(document_items) != package["payload_digest"]:
            problems.append("负载摘要与存储条目不一致")
        header = {
            "package_code": package["package_code"],
            "origin_site": package["origin_site"],
            "sequence": package["sequence"],
            "parent_package_code": package["parent_package_code"],
            "parent_digest": package["parent_digest"],
        }
        if compute_package_digest(header, package["payload_digest"]) != package["package_digest"]:
            problems.append("链式包摘要与存储内容不一致")
        if package["item_count"] != len(items):
            problems.append("条目计数与存储条目数不一致")
        return {"name": "digests", "ok": not problems, "detail": problems or "条目、负载与链式摘要均可独立重算"}

    def _check_signature(self, package: dict[str, Any]) -> dict[str, Any]:
        key = package_signing_key()
        if not key:
            return {"name": "signature", "ok": True, "detail": "未配置 ARCHIVE_PACKAGE_KEY，跳过签名校验"}
        if not package["signature"]:
            return {"name": "signature", "ok": False, "detail": "已配置签名密钥但包缺少签名"}
        ok = hmac.compare_digest(package["signature"], sign_digest(package["package_digest"], key))
        return {"name": "signature", "ok": ok, "detail": "签名校验通过" if ok else "签名校验失败"}

    def _check_parent_chain(self, package: dict[str, Any]) -> dict[str, Any]:
        problems = []
        current = package
        visited = set()
        while current["parent_package_code"]:
            if current["id"] in visited:
                problems.append("父包链存在循环")
                break
            visited.add(current["id"])
            parent = self.packages.by_code(current["origin_site"], current["parent_package_code"])
            if parent is None:
                problems.append(f"父包 {current['parent_package_code']} 不存在")
                break
            if parent["package_digest"] != current["parent_digest"]:
                problems.append(f"父包 {parent['package_code']} 的摘要与记录的父摘要不一致")
            if parent["sequence"] != current["sequence"] - 1:
                problems.append(f"父包 {parent['package_code']} 的序号与本包不连续")
            if parent["direction"] == "imported" and parent["status"] != "committed":
                problems.append(f"父包 {parent['package_code']} 尚未提交完成")
            current = parent
        if current["parent_package_code"] is None and current["sequence"] != 1:
            problems.append("父包链未终止于序号为 1 的首包")
        return {"name": "parent_chain", "ok": not problems, "detail": problems or "父包链完整可溯"}

    def _check_sequence(self, package: dict[str, Any]) -> dict[str, Any]:
        sequences = self.packages.committed_sequences(package["origin_site"])
        expected = list(range(1, (sequences[-1] if sequences else 0) + 1))
        ok = sequences == expected
        detail = "已提交包序号连续无缺口" if ok else f"已提交包序号存在缺口：期望 {expected}，实际 {sequences}"
        return {"name": "sequence", "ok": ok, "detail": detail}

    def _check_items_consistent(self, package: dict[str, Any]) -> dict[str, Any]:
        items = self.packages.items(package["id"])
        problems = []
        if package["status"] == "committed":
            leftover = [item["item_index"] for item in items if item["status"] in ("pending", "failed")]
            if leftover:
                problems.append(f"包已提交但条目 {leftover} 仍未完成")
        if package["status"] == "failed" and not any(item["status"] == "failed" for item in items):
            problems.append("包标记为失败但没有失败条目")
        return {"name": "items_consistent", "ok": not problems, "detail": problems or "包状态与条目状态一致"}

    def _check_audit_trail(self, package: dict[str, Any]) -> dict[str, Any]:
        items = self.packages.items(package["id"])
        problems = []
        for item in items:
            if item["status"] != "applied":
                continue
            audit_count = self.connection.execute(
                """SELECT COUNT(*) FROM audit_events WHERE correlation_id=?
                   AND action IN (?, 'offline.fork.resolve')""",
                (package["package_code"], f"offline.import.{item['item_type']}"),
            ).fetchone()[0]
            if audit_count < 1:
                problems.append(f"条目 {item['item_index']} 缺少审计事件")
            if item["item_type"] in ("dossier_register", "vault_transfer") and item["resource_id"]:
                event_types = ("received", "fork.resolved") if item["item_type"] == "dossier_register" else ("vault.transferred",)
                placeholders = ",".join("?" for _ in event_types)
                event_count = self.connection.execute(
                    f"SELECT COUNT(*) FROM dossier_events WHERE correlation_id=? AND dossier_id=? AND event_type IN ({placeholders})",
                    (package["package_code"], item["resource_id"], *event_types),
                ).fetchone()[0]
                if event_count < 1:
                    problems.append(f"条目 {item['item_index']} 缺少档案事件")
        return {"name": "audit_trail", "ok": not problems, "detail": problems or "每个已应用条目都可追溯到审计与档案事件"}

    def _check_effective_state(self, package: dict[str, Any]) -> dict[str, Any]:
        items = self.packages.items(package["id"])
        problems = []
        checked_dossiers: set[int] = set()
        for item in items:
            if item["status"] != "applied":
                continue
            payload = item["payload"]
            if item["item_type"] == "intake_batch":
                batch = self.connection.execute(
                    "SELECT * FROM intake_batches WHERE intake_code=?", (payload["intake_code"],)
                ).fetchone()
                if batch is None:
                    problems.append(f"移交批次 {payload['intake_code']} 不存在")
                    continue
                actual = self.connection.execute(
                    "SELECT COUNT(*) FROM dossiers WHERE intake_id=?", (batch["id"],)
                ).fetchone()[0]
                if actual != batch["accepted_count"]:
                    problems.append(f"移交批次 {payload['intake_code']} 计数 {batch['accepted_count']} 与实际 {actual} 不一致")
            elif item["item_type"] == "approval_result":
                request = self.connection.execute(
                    "SELECT * FROM approval_requests WHERE request_code=?", (payload["request_code"],)
                ).fetchone()
                if request is None:
                    problems.append(f"审批请求 {payload['request_code']} 不存在")
                    continue
                decisions = self.connection.execute(
                    "SELECT decision FROM approval_decisions WHERE request_id=?", (request["id"],)
                ).fetchall()
                values = [row[0] for row in decisions]
                expected_state = "rejected" if "reject" in values else ("approved" if len(values) >= request["required_approvals"] else "pending")
                if request["state"] not in (expected_state, "executed", "cancelled", "expired"):
                    problems.append(f"审批请求 {payload['request_code']} 状态 {request['state']} 与审批决定不一致")
            elif item["item_type"] in ("dossier_register", "vault_transfer"):
                dossier_id = int(item["resource_id"])
                if dossier_id in checked_dossiers:
                    continue
                checked_dossiers.add(dossier_id)
                dossier = self.connection.execute("SELECT * FROM dossiers WHERE id=?", (dossier_id,)).fetchone()
                if dossier is None:
                    problems.append(f"档案 {dossier_id} 不存在")
                    continue
                latest_transfer = self.connection.execute(
                    """SELECT details_json FROM dossier_events WHERE dossier_id=? AND event_type='vault.transferred'
                       ORDER BY id DESC LIMIT 1""",
                    (dossier_id,),
                ).fetchone()
                if latest_transfer:
                    to_vault_id = json.loads(latest_transfer["details_json"]).get("to_vault_id")
                    if to_vault_id != dossier["vault_id"]:
                        problems.append(
                            f"档案 {dossier['dossier_code']} 当前库位与最新转移事件不一致"
                        )
                base_versions = [
                    entry["payload"]["base_version"]
                    for entry in items
                    if entry["item_type"] == "vault_transfer"
                    and entry["status"] == "applied"
                    and entry["resource_id"] == item["resource_id"]
                ]
                if base_versions and dossier["version"] < max(base_versions) + 1:
                    problems.append(
                        f"档案 {dossier['dossier_code']} 当前版本 {dossier['version']} 低于已应用变更要求的版本"
                    )
        return {"name": "effective_state", "ok": not problems, "detail": problems or "当前有效状态与事件链、版本关系一致"}

    def _check_forks(self, package: dict[str, Any]) -> dict[str, Any]:
        pending = self.packages.list_forks(state="pending", package_id=package["id"])
        if pending:
            return {
                "name": "forks",
                "ok": False,
                "detail": [f"分叉 {fork['fork_code']} 尚未裁决" for fork in pending],
            }
        return {"name": "forks", "ok": True, "detail": "无待裁决分叉"}
