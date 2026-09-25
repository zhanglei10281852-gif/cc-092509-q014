from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import VaultRepository, DossierRepository
from app.services.audit import AuditService


def _row(row: sqlite3.Row | None, message: str) -> dict[str, Any]:
    if row is None:
        raise NotFoundError(message)
    return dict(row)


class InventoryReviewRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_session(
        self,
        session_code: str,
        vault_id: int,
        started_by: int,
        snapshot_version: int,
        now: str,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO inventory_reviews(
                   session_code,vault_id,started_by,state,snapshot_version,
                   started_at,created_at,updated_at
               ) VALUES(?,?,?,'draft',?,?,?,?)""",
            (session_code, vault_id, started_by, snapshot_version, now, now, now),
        )
        return self.get_session(cursor.lastrowid)

    def get_session(self, session_id: int) -> dict[str, Any]:
        session = _row(
            self.connection.execute(
                """SELECT i.*,l.code AS vault_code,l.sensitivity AS vault_sensitivity
                   FROM inventory_reviews i JOIN vault_locations l ON l.id=i.vault_id
                   WHERE i.id=?""",
                (session_id,),
            ).fetchone(),
            "载体盘点会话不存在",
        )
        session["counts"] = [
            dict(row)
            for row in self.connection.execute(
                """SELECT c.*,s.dossier_code,s.quantity AS book_quantity,s.unit,s.lifecycle_state
                   FROM inventory_review_counts c JOIN dossiers s ON s.id=c.dossier_id
                   WHERE c.session_id=? ORDER BY s.dossier_code""",
                (session_id,),
            ).fetchall()
        ]
        return session

    def active_for_vault(self, vault_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT * FROM inventory_reviews
               WHERE vault_id=? AND state NOT IN ('closed','cancelled') ORDER BY id DESC LIMIT 1""",
            (vault_id,),
        ).fetchone()
        return dict(row) if row else None

    def transition(self, session_id: int, expected_state: str, state: str, now: str) -> dict[str, Any]:
        closed_at = now if state == "closed" else None
        cursor = self.connection.execute(
            """UPDATE inventory_reviews SET state=?,closed_at=COALESCE(?,closed_at),updated_at=?
               WHERE id=? AND state=?""",
            (state, closed_at, now, session_id, expected_state),
        )
        if cursor.rowcount != 1:
            raise ConflictError("载体盘点会话状态已变化")
        return self.get_session(session_id)

    def upsert_count(
        self,
        session_id: int,
        dossier_id: int,
        observed_quantity: float | None,
        observed_present: bool,
        counted_by: int,
        note: str,
        now: str,
    ) -> dict[str, Any]:
        self.connection.execute(
            """INSERT INTO inventory_review_counts(
                   session_id,dossier_id,observed_quantity,observed_present,counted_by,counted_at,note
               ) VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(session_id,dossier_id) DO UPDATE SET
                   observed_quantity=excluded.observed_quantity,
                   observed_present=excluded.observed_present,
                   counted_by=excluded.counted_by,
                   counted_at=excluded.counted_at,
                   note=excluded.note""",
            (session_id, dossier_id, observed_quantity, int(observed_present), counted_by, now, note),
        )
        return dict(
            self.connection.execute(
                "SELECT * FROM inventory_review_counts WHERE session_id=? AND dossier_id=?",
                (session_id, dossier_id),
            ).fetchone()
        )

    def expected_dossiers(self, vault_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT * FROM dossiers WHERE vault_id=?
               AND lifecycle_state NOT IN ('disposed','disclosed') ORDER BY dossier_code""",
            (vault_id,),
        ).fetchall()
        return [dict(row) for row in rows]


class InventoryReviewService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.inventory_review = InventoryReviewRepository(connection)
        self.vaults = VaultRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def start(self, principal: Principal, vault_id: int, session_code: str | None = None) -> dict[str, Any]:
        principal.require("inventory_review.manage")
        self.vaults.get(vault_id)
        if self.inventory_review.active_for_vault(vault_id):
            raise ConflictError("该位置已有未结束的载体盘点")
        now = to_storage(self.clock.now())
        snapshot = int(
            self.connection.execute(
                "SELECT COALESCE(MAX(version),0) FROM dossiers WHERE vault_id=?",
                (vault_id,),
            ).fetchone()[0]
        )
        code = session_code or f"INV-{uuid.uuid4().hex[:12]}"
        session = self.inventory_review.create_session(code, vault_id, principal.user_id, snapshot, now)
        session = self.inventory_review.transition(session["id"], "draft", "counting", now)
        self.audit.record(
            principal,
            "inventory_review.start",
            "inventory_review_session",
            str(session["id"]),
            after=session,
            metadata={"vault_id": vault_id, "snapshot_version": snapshot},
        )
        return session

    def count(
        self,
        principal: Principal,
        session_id: int,
        dossier_id: int,
        observed_present: bool,
        observed_quantity: float | None,
        note: str = "",
    ) -> dict[str, Any]:
        principal.require("inventory_review.manage")
        session = self.inventory_review.get_session(session_id)
        if session["state"] != "counting":
            raise ConflictError("载体盘点会话不在计数阶段")
        dossier = self.dossiers.get(dossier_id)
        if dossier["vault_id"] != session["vault_id"]:
            raise ValidationError("档案不属于本次载体盘点位置")
        if observed_present and observed_quantity is None:
            raise ValidationError("发现档案时必须填写实盘数量")
        if observed_quantity is not None and observed_quantity < 0:
            raise ValidationError("实盘数量不能为负数")
        return self.inventory_review.upsert_count(
            session_id,
            dossier_id,
            observed_quantity,
            observed_present,
            principal.user_id,
            note,
            to_storage(self.clock.now()),
        )

    def reconcile(self, principal: Principal, session_id: int) -> dict[str, Any]:
        principal.require("inventory_review.manage")
        before = self.inventory_review.get_session(session_id)
        if before["state"] != "counting":
            raise ConflictError("只有计数中的载体盘点可以生成差异")
        expected = self.inventory_review.expected_dossiers(before["vault_id"])
        counts = {item["dossier_id"]: item for item in before["counts"]}
        differences = []
        for dossier in expected:
            count = counts.get(dossier["id"])
            if count is None:
                differences.append(
                    {
                        "dossier_id": dossier["id"],
                        "dossier_code": dossier["dossier_code"],
                        "kind": "not_counted",
                        "book_quantity": dossier["quantity"],
                        "observed_quantity": None,
                    }
                )
                continue
            if not count["observed_present"]:
                differences.append(
                    {
                        "dossier_id": dossier["id"],
                        "dossier_code": dossier["dossier_code"],
                        "kind": "missing",
                        "book_quantity": dossier["quantity"],
                        "observed_quantity": None,
                    }
                )
                continue
            observed = float(count["observed_quantity"])
            if abs(observed - dossier["quantity"]) > 1e-9:
                differences.append(
                    {
                        "dossier_id": dossier["id"],
                        "dossier_code": dossier["dossier_code"],
                        "kind": "quantity_mismatch",
                        "book_quantity": dossier["quantity"],
                        "observed_quantity": observed,
                        "delta": observed - dossier["quantity"],
                    }
                )
        now = to_storage(self.clock.now())
        session = self.inventory_review.transition(session_id, "counting", "reconciling", now)
        digest = hashlib.sha256(
            json.dumps(differences, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.audit.record(
            principal,
            "inventory_review.reconcile",
            "inventory_review_session",
            str(session_id),
            before=before,
            after=session,
            metadata={"difference_count": len(differences), "difference_digest": digest},
        )
        return {"session": session, "differences": differences, "digest": digest}

    def close_without_adjustment(self, principal: Principal, session_id: int) -> dict[str, Any]:
        principal.require("inventory_review.manage")
        before = self.inventory_review.get_session(session_id)
        if before["state"] != "reconciling":
            raise ConflictError("载体盘点会话尚未进入差异复核阶段")
        expected = self.inventory_review.expected_dossiers(before["vault_id"])
        counts = {item["dossier_id"]: item for item in before["counts"]}
        unresolved = []
        for dossier in expected:
            count = counts.get(dossier["id"])
            if count is None or not count["observed_present"]:
                unresolved.append(dossier["dossier_code"])
            elif abs(float(count["observed_quantity"]) - dossier["quantity"]) > 1e-9:
                unresolved.append(dossier["dossier_code"])
        if unresolved:
            raise ConflictError("仍有未处理载体盘点差异", context={"dossier_codes": unresolved})
        result = self.inventory_review.transition(
            session_id, "reconciling", "closed", to_storage(self.clock.now())
        )
        self.audit.record(
            principal,
            "inventory_review.close",
            "inventory_review_session",
            str(session_id),
            before=before,
            after=result,
        )
        return result


class ArchiveSummaryService:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def by_vault(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        rows = self.connection.execute(
            """SELECT l.id,l.code,l.sensitivity,l.capacity_units,
                      COUNT(s.id) AS dossier_count,
                      COALESCE(SUM(CASE WHEN s.lifecycle_state NOT IN ('disposed','disclosed') THEN s.quantity ELSE 0 END),0) AS quantity,
                      SUM(CASE WHEN s.lifecycle_state='access_loaned' THEN 1 ELSE 0 END) AS access_loaned_count,
                      SUM(CASE WHEN s.lifecycle_state='quarantined' THEN 1 ELSE 0 END) AS quarantined_count
               FROM vault_locations l LEFT JOIN dossiers s ON s.vault_id=l.id
               WHERE l.active=1 GROUP BY l.id ORDER BY l.code"""
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if item["sensitivity"] != "normal" and not (
                "*" in principal.permissions or "vaults.read_sensitive" in principal.permissions
            ):
                item["code"] = f"MASKED-{item['id']:04d}"
            result.append(item)
        return result

    def by_state(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        rows = self.connection.execute(
            """SELECT lifecycle_state,unit,COUNT(*) AS dossier_count,SUM(quantity) AS quantity,
                      SUM(reserved_quantity) AS reserved_quantity
               FROM dossiers GROUP BY lifecycle_state,unit ORDER BY lifecycle_state,unit"""
        ).fetchall()
        return [dict(row) for row in rows]
