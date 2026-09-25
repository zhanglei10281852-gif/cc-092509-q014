from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage
from app.core.errors import NotFoundError
from app.core.security import Principal


class BatchReconciliationService:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def detail(self, principal: Principal, intake_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        batch = self.connection.execute(
            "SELECT * FROM intake_batches WHERE id=?", (intake_id,)
        ).fetchone()
        if not batch:
            raise NotFoundError("移交批次不存在")
        dossiers = [
            dict(row)
            for row in self.connection.execute(
                """SELECT id,dossier_code,asset_type,quantity,reserved_quantity,unit,
                          lifecycle_state,vault_id,source_dossier_id,root_dossier_id
                   FROM dossiers WHERE intake_id=? ORDER BY dossier_code""",
                (intake_id,),
            ).fetchall()
        ]
        by_state: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)
        quantities: dict[str, float] = defaultdict(float)
        unlocated = []
        for dossier in dossiers:
            by_state[dossier["lifecycle_state"]] += 1
            by_type[dossier["asset_type"]] += 1
            quantities[dossier["unit"]] += float(dossier["quantity"])
            if dossier["vault_id"] is None and dossier["lifecycle_state"] not in {
                "access_loaned", "disclosed", "disposed"
            }:
                unlocated.append(dossier["dossier_code"])
        accepted = len(dossiers)
        expected = int(batch["expected_count"])
        return {
            "batch": dict(batch),
            "dossier_count": accepted,
            "count_delta": accepted - expected,
            "is_count_reconciled": accepted + int(batch["rejected_count"]) == expected,
            "by_state": dict(sorted(by_state.items())),
            "by_type": dict(sorted(by_type.items())),
            "quantity_by_unit": dict(sorted(quantities.items())),
            "unlocated_dossier_codes": unlocated,
            "dossiers": dossiers,
        }

    def open_batches(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        rows = self.connection.execute(
            """SELECT b.*,
                      COUNT(s.id) AS actual_count,
                      SUM(CASE WHEN s.vault_id IS NULL THEN 1 ELSE 0 END) AS unlocated_count
               FROM intake_batches b LEFT JOIN dossiers s ON s.intake_id=b.id
               WHERE b.status IN ('open','reconciled','quarantined')
               GROUP BY b.id ORDER BY b.received_at,b.id"""
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["count_delta"] = int(item["actual_count"]) + int(item["rejected_count"]) - int(item["expected_count"])
            result.append(item)
        return result


class ExceptionAgingService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()

    def summary(self, principal: Principal) -> dict[str, Any]:
        principal.require("dossiers.read")
        now = self.clock.now()
        cases = [
            dict(row)
            for row in self.connection.execute(
                """SELECT * FROM incident_cases
                   WHERE state NOT IN ('resolved','dismissed') ORDER BY created_at,id"""
            ).fetchall()
        ]
        overdue_access_loans = [
            dict(row)
            for row in self.connection.execute(
                """SELECT l.*,s.dossier_code,u.display_name AS borrower_name
                   FROM access_loans l JOIN dossiers s ON s.id=l.dossier_id
                   JOIN users u ON u.id=l.requester_user_id
                   WHERE l.state IN ('active','partially_returned','overdue') AND l.due_at<?
                   ORDER BY l.due_at""",
                (now.isoformat(),),
            ).fetchall()
        ]
        aging = {"0-1d": 0, "2-3d": 0, "4-7d": 0, "8d+": 0}
        critical = []
        for case in cases:
            created = from_storage(case["created_at"])
            days = max(0, int((now - created).total_seconds() // 86400))
            if days <= 1:
                bucket = "0-1d"
            elif days <= 3:
                bucket = "2-3d"
            elif days <= 7:
                bucket = "4-7d"
            else:
                bucket = "8d+"
            aging[bucket] += 1
            case["age_days"] = days
            if case["severity"] == "critical":
                critical.append(case)
        return {
            "open_incident_count": len(cases),
            "incident_aging": aging,
            "critical_incidents": critical,
            "overdue_access_loan_count": len(overdue_access_loans),
            "overdue_access_loans": overdue_access_loans,
        }
