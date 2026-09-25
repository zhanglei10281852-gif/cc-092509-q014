from __future__ import annotations


def create_vault(client, admin, code="L-A-01", sensitivity="restricted"):
    response = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={"code": code, "building": "科研楼", "room": "低温间", "cabinet": "柜一", "shelf": "二层", "sensitivity": sensitivity, "capacity_units": 100},
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_batch_dossier(client, admin):
    vault = create_vault(client, admin)
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "BATCH-2026-001", "project_code": "P-ALPHA", "expected_count": 2},
    )
    assert batch.status_code == 201, batch.text
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={"dossier_code": "S-001", "intake_id": batch.json()["id"], "asset_type": "土壤", "quantity": 100, "unit": "g", "vault_id": vault["id"]},
    )
    assert dossier.status_code == 201, dossier.text
    return batch.json(), dossier.json()


def test_receive_and_vault_masking(client, admin):
    _, dossier = create_batch_dossier(client, admin)
    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"])
    assert detail.status_code == 200
    assert detail.json()["vault_code"] == "L-A-01"
    assert detail.json()["events"][0]["event_type"] == "received"


def test_issue_copy_preserves_mass_and_provenance(client, admin):
    _, dossier = create_batch_dossier(client, admin)
    response = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={
            "requested_quantity": 30,
            "loss_quantity": 2,
            "children": [{"dossier_code": "S-001-A", "quantity": 10}, {"dossier_code": "S-001-B", "quantity": 18}],
            "note": "两份检测子样",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["parent"]["quantity"] == 70
    assert [item["source_dossier_id"] for item in response.json()["children"]] == [dossier["id"], dossier["id"]]


def test_consumption_is_idempotent(client, admin):
    _, dossier = create_batch_dossier(client, admin)
    payload = {"recipient_code": "EXP-01", "quantity": 12.5, "idempotency_key": "disclose-001", "note": "理化检测"}
    first = client.post(f"/api/dossiers/{dossier['id']}/disclosures", headers=admin["headers"], json=payload)
    second = client.post(f"/api/dossiers/{dossier['id']}/disclosures", headers=admin["headers"], json=payload)
    assert first.status_code == second.status_code == 201
    assert first.json()["dossier"]["quantity"] == second.json()["dossier"]["quantity"] == 87.5
    assert second.json()["replayed"] is True


def test_access_loan_partial_and_full_return(client, admin):
    _, dossier = create_batch_dossier(client, admin)
    access_loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "requester_user_id": admin["body"]["user"]["id"], "quantity": 20, "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert access_loan.status_code == 201, access_loan.text
    partial = client.post(f"/api/dossiers/access_loans/{access_loan.json()['id']}/returns", headers=admin["headers"], json={"quantity": 5})
    finished = client.post(f"/api/dossiers/access_loans/{access_loan.json()['id']}/returns", headers=admin["headers"], json={"quantity": 15})
    assert partial.json()["state"] == "partially_returned"
    assert finished.json()["state"] == "returned"


def test_two_distinct_approvers_required(client, admin):
    _, dossier = create_batch_dossier(client, admin)
    approval = client.post(
        "/api/dossiers/approvals",
        headers=admin["headers"],
        json={"action_type": "disposal", "resource_type": "dossier", "resource_id": dossier["id"], "payload": {"quantity": 10}},
    )
    assert approval.status_code == 201
    own = client.post(f"/api/dossiers/approvals/{approval.json()['id']}/decisions", headers=admin["headers"], json={"decision": "approve"})
    assert own.status_code == 422


def test_incident_requires_business_target(client, admin):
    response = client.post(
        "/api/dossiers/incidents",
        headers=admin["headers"],
        json={"incident_type": "标签破损", "severity": "high", "description": "二维码与人工标签无法对应"},
    )
    assert response.status_code == 422
