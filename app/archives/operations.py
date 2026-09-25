from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import ApprovalRepository, VaultRepository, DossierRepository
from app.services.audit import AuditService


class DisclosureService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.audit = AuditService(connection, self.clock)

    def register(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        existing = self.connection.execute(
            "SELECT * FROM disclosure_events WHERE disclosure_code=?", (data["disclosure_code"],)
        ).fetchone()
        if existing:
            if dict(existing)["chain_digest"] != self._chain_digest(data):
                raise ConflictError("现场编号已被不同采集信息占用")
            return {**dict(existing), "replayed": True}
        now = to_storage(self.clock.now())
        digest = self._chain_digest(data)
        cursor = self.connection.execute(
            """INSERT INTO disclosure_events(
                   disclosure_code,project_code,submitted_by,submitted_at,source_kind,
                   source_reference,quantity,unit,preservation,chain_digest,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["disclosure_code"], data["project_code"], data["submitted_by"],
                data["submitted_at"], data["source_kind"], data["source_reference"],
                data["quantity"], data["unit"], data["preservation"], digest, now,
            ),
        )
        event = dict(
            self.connection.execute(
                "SELECT * FROM disclosure_events WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )
        self.audit.record(
            principal, "collection.register", "collection_event", str(event["id"]), after=event
        )
        return {**event, "replayed": False}

    def _chain_digest(self, data: dict[str, Any]) -> str:
        canonical = json.dumps(
            {
                key: data[key]
                for key in (
                    "disclosure_code", "project_code", "submitted_by", "submitted_at",
                    "source_kind", "source_reference", "quantity", "unit", "preservation",
                )
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TransferService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.vaults = VaultRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def move(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        before = self.dossiers.get(dossier_id)
        target = self.vaults.get(data["vault_id"])
        if before["lifecycle_state"] in {"access_loaned", "pending_disposal", "disposed"}:
            raise ConflictError("当前状态禁止转移密级库位")
        if before["vault_id"] == target["id"]:
            return {"dossier": before, "replayed": True}
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            """UPDATE dossiers SET vault_id=?,custody_user_id=?,version=version+1,updated_at=?
               WHERE id=? AND version=?""",
            (target["id"], principal.user_id, now, dossier_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("档案位置或版本已变化")
        after = self.dossiers.get(dossier_id)
        self.dossiers.append_event(
            dossier_id,
            "vault.transferred",
            principal.user_id,
            now,
            details={
                "from_vault_id": before["vault_id"],
                "to_vault_id": target["id"],
                "reason": data["reason"],
            },
            correlation_id=data.get("correlation_id"),
        )
        self.audit.record(
            principal,
            "dossier.transfer",
            "dossier",
            str(dossier_id),
            before=before,
            after=after,
            metadata={"reason": data["reason"]},
        )
        return {"dossier": after, "replayed": False}


class DisposalService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.approvals = ApprovalRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def execute(self, principal: Principal, request_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.dispose")
        approval = self.approvals.get(request_id)
        if approval["action_type"] != "disposal":
            raise ValidationError("审批请求不是合规处置类型")
        if approval["state"] != "approved":
            raise ConflictError("合规处置请求尚未完成双人审批")
        if approval["requested_by"] in {data["witness_one"], data["witness_two"]}:
            raise ValidationError("申请人不能同时作为合规处置见证人")
        if data["witness_one"] == data["witness_two"]:
            raise ValidationError("两名见证人必须不同")
        existing = self.connection.execute(
            "SELECT * FROM disposal_records WHERE request_id=?", (request_id,)
        ).fetchone()
        if existing:
            return {"record": dict(existing), "dossier": self.dossiers.get(approval["resource_id"]), "replayed": True}
        dossier = self.dossiers.get(approval["resource_id"])
        quantity = float(approval["payload"].get("quantity", dossier["quantity"]))
        if quantity <= 0 or quantity > dossier["quantity"] - dossier["reserved_quantity"]:
            raise ConflictError("审批数量超过当前可合规处置数量")
        now = to_storage(self.clock.now())
        remaining = dossier["quantity"] - quantity
        updated = self.dossiers.change_quantity(dossier["id"], -quantity, dossier["version"], now)
        target_state = "disposed" if remaining == 0 else "partially_disclosed"
        updated = self.dossiers.set_state(dossier["id"], target_state, updated["version"], now)
        certificate = hashlib.sha256(
            json.dumps(
                {
                    "request_id": request_id,
                    "dossier_id": dossier["id"],
                    "quantity": quantity,
                    "method": data["method"],
                    "witnesses": sorted([data["witness_one"], data["witness_two"]]),
                    "disposed_at": now,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        cursor = self.connection.execute(
            """INSERT INTO disposal_records(
                   dossier_id,request_id,method,witness_one,witness_two,disposed_quantity,
                   certificate_digest,disposed_at,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                dossier["id"], request_id, data["method"], data["witness_one"],
                data["witness_two"], quantity, certificate, now, now,
            ),
        )
        self.connection.execute(
            "UPDATE approval_requests SET state='executed',version=version+1,updated_at=? WHERE id=?",
            (now, request_id),
        )
        record = dict(
            self.connection.execute(
                "SELECT * FROM disposal_records WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )
        self.dossiers.append_event(
            dossier["id"],
            "disposed",
            principal.user_id,
            now,
            quantity_delta=-quantity,
            from_state=dossier["lifecycle_state"],
            to_state=target_state,
            details={"request_id": request_id, "certificate_digest": certificate},
        )
        self.audit.record(
            principal,
            "dossier.dispose",
            "dossier",
            str(dossier["id"]),
            before=dossier,
            after=updated,
            metadata={"request_id": request_id, "certificate_digest": certificate},
        )
        return {"record": record, "dossier": updated, "replayed": False}


class ProvenanceService:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def graph(self, principal: Principal, dossier_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        dossier = self.connection.execute("SELECT * FROM dossiers WHERE id=?", (dossier_id,)).fetchone()
        if not dossier:
            raise NotFoundError("档案不存在")
        root_id = dossier["root_dossier_id"] or dossier["id"]
        rows = self.connection.execute(
            "SELECT * FROM dossiers WHERE root_dossier_id=? OR id=? ORDER BY provenance_depth,id",
            (root_id, root_id),
        ).fetchall()
        nodes = [dict(row) for row in rows]
        edges = [
            {"source_dossier_id": node["source_dossier_id"], "child_dossier_id": node["id"]}
            for node in nodes
            if node["source_dossier_id"]
        ]
        totals: dict[str, float] = {}
        for node in nodes:
            totals[node["unit"]] = totals.get(node["unit"], 0.0) + float(node["quantity"])
        return {"root_dossier_id": root_id, "nodes": nodes, "edges": edges, "remaining_by_unit": totals}
