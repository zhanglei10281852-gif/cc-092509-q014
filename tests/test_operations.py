from __future__ import annotations


def _bootstrap_dossier(client, admin):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "OPS-01",
            "building": "档案楼",
            "room": "常温库",
            "cabinet": "三号柜",
            "shelf": "二层",
            "sensitivity": "normal",
            "capacity_units": 50,
        },
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "OPS-BATCH", "project_code": "OPS", "expected_count": 1},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "OPS-SAMPLE",
            "intake_id": batch["id"],
            "asset_type": "水样",
            "quantity": 20,
            "unit": "mL",
            "vault_id": vault["id"],
        },
    ).json()
    return vault, batch, dossier


def test_collection_registration_is_idempotent(client, admin):
    payload = {
        "disclosure_code": "FIELD-001",
        "project_code": "OPS",
        "submitted_by": "野外组甲",
        "submitted_at": "2026-09-25T08:00:00+00:00",
        "source_kind": "河水",
        "source_reference": "断面 A",
        "quantity": 500,
        "unit": "mL",
        "preservation": "4 摄氏度避光",
    }
    first = client.post("/api/dossier-operations/disclosures", headers=admin["headers"], json=payload)
    second = client.post("/api/dossier-operations/disclosures", headers=admin["headers"], json=payload)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["replayed"] is True


def test_inventory_review_reconciles_and_closes(client, admin):
    vault, _, dossier = _bootstrap_dossier(client, admin)
    session = client.post(
        "/api/dossier-operations/inventory_review",
        headers=admin["headers"],
        json={"vault_id": vault["id"], "session_code": "INV-OPS-01"},
    )
    assert session.status_code == 201, session.text
    count = client.post(
        f"/api/dossier-operations/inventory_review/{session.json()['id']}/counts",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "observed_present": True, "observed_quantity": 20},
    )
    assert count.status_code == 200, count.text
    reconciled = client.post(
        f"/api/dossier-operations/inventory_review/{session.json()['id']}/reconcile",
        headers=admin["headers"],
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["differences"] == []
    closed = client.post(
        f"/api/dossier-operations/inventory_review/{session.json()['id']}/close",
        headers=admin["headers"],
    )
    assert closed.status_code == 200
    assert closed.json()["state"] == "closed"


def test_transfer_updates_provenance_event(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    target = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "OPS-02",
            "building": "档案楼",
            "room": "低温库",
            "cabinet": "一号柜",
            "shelf": "一层",
            "sensitivity": "restricted",
            "capacity_units": 50,
        },
    ).json()
    moved = client.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        headers=admin["headers"],
        json={"vault_id": target["id"], "expected_version": dossier["version"], "reason": "转入低温保存"},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["dossier"]["vault_id"] == target["id"]
    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"])
    assert detail.json()["events"][-1]["event_type"] == "vault.transferred"
