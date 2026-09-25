from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import IncidentRepository, ApprovalRepository, IntakeRepository, VaultRepository, DossierRepository
from app.archives.validation import require_code
from app.services.audit import AuditService


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class VaultService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.vaults = VaultRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        if self.vaults.by_code(data["code"]):
            raise ConflictError("位置编码已经存在")
        now = to_storage(self.clock.now())
        vault = self.vaults.create(data, now)
        self.audit.record(principal, "vault.create", "storage_vault", str(vault["id"]), after=vault)
        return self.present(principal, vault)

    def present(self, principal: Principal, vault: dict[str, Any]) -> dict[str, Any]:
        result = dict(vault)
        exact = "*" in principal.permissions or "vaults.read_sensitive" in principal.permissions
        if not exact and vault["sensitivity"] != "normal":
            result["building"] = "受限区域"
            result["room"] = "***"
            result["cabinet"] = "***"
            result["shelf"] = "***"
            result["code"] = f"MASKED-{vault['id']:04d}"
        return result

    def list(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return [self.present(principal, item) for item in self.vaults.list()]


class DossierLifecycleService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.batches = IntakeRepository(connection)
        self.vaults = VaultRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create_batch(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        now = to_storage(self.clock.now())
        payload = f"dossier-batch:{data['intake_code']}:{data['project_code']}"
        batch = self.batches.create(data, principal.user_id, payload, now)
        self.audit.record(principal, "batch.receive", "receipt_batch", str(batch["id"]), after=batch)
        return batch

    def register_dossier(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        data = {**data, "dossier_code": require_code(data["dossier_code"], "档案编码")}
        if self.dossiers.by_code(data["dossier_code"]):
            raise ConflictError("档案编码已经存在")
        self.batches.get(data["intake_id"])
        if data.get("vault_id"):
            self.vaults.get(data["vault_id"])
        now = to_storage(self.clock.now())
        values = dict(data)
        values.update(lifecycle_state="available", custody_user_id=principal.user_id, provenance_depth=0)
        dossier = self.dossiers.create(values, now)
        self.dossiers.append_event(dossier["id"], "received", principal.user_id, now, to_state="available", details={"intake_id": data["intake_id"]})
        self.batches.update_counts(data["intake_id"], now)
        self.audit.record(principal, "dossier.register", "dossier", str(dossier["id"]), after=dossier)
        return dossier

    def list_dossiers(self, principal: Principal, state: str | None, intake_id: int | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        exact = "*" in principal.permissions or "vaults.read_sensitive" in principal.permissions
        result = self.dossiers.list(state=state, intake_id=intake_id)
        for dossier in result:
            if dossier.get("vault_sensitivity") != "normal" and not exact:
                dossier["vault_code"] = f"MASKED-{dossier['vault_id']:04d}" if dossier.get("vault_id") else None
        return result

    def detail(self, principal: Principal, dossier_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        dossier = self.dossiers.get(dossier_id)
        dossier["events"] = self.dossiers.events(dossier_id)
        dossier["children"] = self.dossiers.children(dossier_id)
        if dossier.get("vault_sensitivity") != "normal" and not (
            "*" in principal.permissions or "vaults.read_sensitive" in principal.permissions
        ):
            dossier["vault_code"] = f"MASKED-{dossier['vault_id']:04d}" if dossier.get("vault_id") else None
        return dossier

    def issue_copy(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        parent = self.dossiers.get(dossier_id)
        total = round(sum(item["quantity"] for item in data["children"]) + data.get("loss_quantity", 0), 9)
        if abs(total - data["requested_quantity"]) > 1e-6:
            raise ValidationError("子样数量与损耗之和必须等于受控副本签发数量")
        if parent["quantity"] - parent["reserved_quantity"] < data["requested_quantity"]:
            raise ConflictError("可用数量不足")
        now = to_storage(self.clock.now())
        updated_parent = self.dossiers.change_quantity(dossier_id, -data["requested_quantity"], parent["version"], now)
        children = []
        for item in data["children"]:
            child = self.dossiers.create(
                {
                    "dossier_code": item["dossier_code"],
                    "intake_id": parent["intake_id"],
                    "disclosure_event_id": parent["disclosure_event_id"],
                    "source_dossier_id": dossier_id,
                    "root_dossier_id": parent["root_dossier_id"],
                    "asset_type": parent["asset_type"],
                    "quantity": item["quantity"],
                    "unit": parent["unit"],
                    "lifecycle_state": "available",
                    "vault_id": item.get("vault_id", parent["vault_id"]),
                    "custody_user_id": principal.user_id,
                    "provenance_depth": parent["provenance_depth"] + 1,
                },
                now,
            )
            self.dossiers.append_event(child["id"], "issue_copy.created", principal.user_id, now, to_state="available", details={"source_dossier_id": dossier_id})
            children.append(child)
        operation_code = data.get("operation_code") or f"ALI-{uuid.uuid4().hex[:12]}"
        self.connection.execute(
            """INSERT INTO copy_issue_operations(operation_code,source_dossier_id,requested_quantity,produced_quantity,loss_quantity,operator_user_id,occurred_at,note,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (operation_code, dossier_id, data["requested_quantity"], sum(item["quantity"] for item in data["children"]), data.get("loss_quantity", 0), principal.user_id, now, data.get("note", ""), now),
        )
        self.dossiers.append_event(dossier_id, "issue_copy.source", principal.user_id, now, quantity_delta=-data["requested_quantity"], details={"operation_code": operation_code, "child_ids": [item["id"] for item in children]})
        self.audit.record(principal, "dossier.issue_copy", "dossier", str(dossier_id), before=parent, after=updated_parent, metadata={"operation_code": operation_code})
        return {"operation_code": operation_code, "parent": updated_parent, "children": children}

    def disclose(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.disclose")
        dossier = self.dossiers.get(dossier_id)
        if dossier["lifecycle_state"] in {"disposed", "pending_disposal", "quarantined"}:
            raise ConflictError("当前状态禁止披露使用")
        existing = self.connection.execute(
            "SELECT * FROM disclosure_use_records WHERE dossier_id=? AND idempotency_key=?",
            (dossier_id, data["idempotency_key"]),
        ).fetchone()
        if existing:
            return {"record": dict(existing), "dossier": self.dossiers.get(dossier_id), "replayed": True}
        if dossier["quantity"] - dossier["reserved_quantity"] < data["quantity"]:
            raise ConflictError("可用数量不足")
        now = to_storage(self.clock.now())
        updated = self.dossiers.change_quantity(dossier_id, -data["quantity"], dossier["version"], now)
        new_state = "disclosed" if updated["quantity"] == 0 else "partially_disclosed"
        updated = self.dossiers.set_state(dossier_id, new_state, updated["version"], now)
        cursor = self.connection.execute(
            """INSERT INTO disclosure_use_records(dossier_id,recipient_code,quantity,operator_user_id,idempotency_key,occurred_at,note,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (dossier_id, data["recipient_code"], data["quantity"], principal.user_id, data["idempotency_key"], now, data.get("note", ""), now),
        )
        record = dict(self.connection.execute("SELECT * FROM disclosure_use_records WHERE id=?", (cursor.lastrowid,)).fetchone())
        self.dossiers.append_event(dossier_id, "disclosed", principal.user_id, now, quantity_delta=-data["quantity"], from_state=dossier["lifecycle_state"], to_state=new_state, details={"recipient_code": data["recipient_code"]})
        self.audit.record(principal, "dossier.disclose", "dossier", str(dossier_id), before=dossier, after=updated)
        return {"record": record, "dossier": updated, "replayed": False}


class AccessLoanService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_loans.manage")
        dossier = self.dossiers.get(data["dossier_id"])
        if dossier["lifecycle_state"] not in {"available", "partially_disclosed"}:
            raise ConflictError("档案当前不可查阅借阅")
        if dossier["quantity"] - dossier["reserved_quantity"] < data["quantity"]:
            raise ConflictError("可借数量不足")
        now = to_storage(self.clock.now())
        access_code = data.get("access_code") or f"LOAN-{uuid.uuid4().hex[:12]}"
        cursor = self.connection.execute(
            """INSERT INTO access_loans(access_code,dossier_id,requester_user_id,quantity,due_at,state,created_at,updated_at)
               VALUES(?,?,?,?,?,'active',?,?)""",
            (access_code, data["dossier_id"], data["requester_user_id"], data["quantity"], data["due_at"], now, now),
        )
        self.connection.execute(
            "UPDATE dossiers SET reserved_quantity=reserved_quantity+?,lifecycle_state='access_loaned',version=version+1,updated_at=? WHERE id=?",
            (data["quantity"], now, data["dossier_id"]),
        )
        access_loan = dict(self.connection.execute("SELECT * FROM access_loans WHERE id=?", (cursor.lastrowid,)).fetchone())
        self.dossiers.append_event(data["dossier_id"], "access_loaned", principal.user_id, now, from_state=dossier["lifecycle_state"], to_state="access_loaned", details={"access_loan_id": access_loan["id"], "requester_user_id": data["requester_user_id"]})
        self.audit.record(principal, "access_loan.create", "access_loan", str(access_loan["id"]), after=access_loan)
        return access_loan

    def return_access_loan(self, principal: Principal, access_loan_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_loans.manage")
        access_loan_row = self.connection.execute("SELECT * FROM access_loans WHERE id=?", (access_loan_id,)).fetchone()
        if not access_loan_row:
            raise NotFoundError("查阅借阅记录不存在")
        access_loan = dict(access_loan_row)
        if access_loan["state"] not in {"active", "partially_returned", "overdue"}:
            raise ConflictError("查阅借阅记录已经结束")
        remaining = access_loan["quantity"] - access_loan["returned_quantity"]
        if data["quantity"] > remaining:
            raise ValidationError("归还数量超过未归还数量")
        now = to_storage(self.clock.now())
        returned = access_loan["returned_quantity"] + data["quantity"]
        state = "returned" if abs(returned - access_loan["quantity"]) < 1e-9 else "partially_returned"
        self.connection.execute(
            "UPDATE access_loans SET returned_quantity=?,state=?,version=version+1,updated_at=? WHERE id=?",
            (returned, state, now, access_loan_id),
        )
        self.connection.execute(
            """UPDATE dossiers SET reserved_quantity=reserved_quantity-?,
               lifecycle_state=CASE WHEN reserved_quantity-?=0 THEN CASE WHEN quantity=0 THEN 'disclosed' ELSE 'available' END ELSE 'access_loaned' END,
               version=version+1,updated_at=? WHERE id=?""",
            (data["quantity"], data["quantity"], now, access_loan["dossier_id"]),
        )
        result = dict(self.connection.execute("SELECT * FROM access_loans WHERE id=?", (access_loan_id,)).fetchone())
        self.dossiers.append_event(access_loan["dossier_id"], "returned", principal.user_id, now, quantity_delta=0, details={"access_loan_id": access_loan_id, "returned_quantity": data["quantity"]})
        self.audit.record(principal, "access_loan.return", "access_loan", str(access_loan_id), before=access_loan, after=result)
        return result


class ApprovalService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.approvals = ApprovalRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        if data["action_type"] == "disposal":
            principal.require("dossiers.dispose")
        elif data["action_type"] == "inventory_review_adjustment":
            principal.require("inventory_review.manage")
        else:
            principal.require("dossiers.write")
        now_dt = self.clock.now()
        values = dict(data)
        values["expires_at"] = values.get("expires_at") or to_storage(now_dt + timedelta(days=3))
        request_code = values.get("request_code") or f"APR-{uuid.uuid4().hex[:12]}"
        request = self.approvals.create(values, principal.user_id, request_code, to_storage(now_dt))
        self.audit.record(principal, "approval.request", "approval_request", str(request["id"]), after=request)
        return request

    def decide(self, principal: Principal, request_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("approvals.decide")
        before = self.approvals.get(request_id)
        result = self.approvals.decide(request_id, principal.user_id, data["decision"], data.get("comment", ""), to_storage(self.clock.now()))
        self.audit.record(principal, "approval.decide", "approval_request", str(request_id), before=before, after=result)
        return result


class IncidentService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.incidents = IncidentRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("incidents.manage")
        if not data.get("dossier_id") and not data.get("intake_id"):
            raise ValidationError("泄密事件必须关联档案或移交批次")
        if data.get("dossier_id"):
            self.dossiers.get(data["dossier_id"])
        case_code = data.get("case_code") or f"ANM-{uuid.uuid4().hex[:12]}"
        case = self.incidents.create(data, principal.user_id, case_code, to_storage(self.clock.now()))
        self.audit.record(principal, "incident.create", "incident_case", str(case["id"]), after=case)
        return case

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.incidents.list(state)
