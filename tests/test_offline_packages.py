"""离线移交包的端到端测试：双站点（分支/总部）各用独立数据库仿真。"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.archives.offline import build_package_document
from app.database import close_connection, init_db

ADMIN_PASSWORD = "Admin!23456"


class Site:
    """一个独立站点：自己的数据库文件、站点标识与管理员会话。

    连接是线程局部的，而 TestClient 在独立线程中执行请求，因此切换站点时
    需要重建 TestClient，让新的请求线程按新的数据库路径建立连接。
    """

    _all: list["Site"] = []

    def __init__(self, path, site_id):
        self.path = path
        self.site_id = site_id
        self.headers = None
        self.client = None
        self._cm = None
        Site._all.append(self)

    def activate(self):
        os.environ["ARCHIVE_DATABASE_PATH"] = str(self.path)
        os.environ["ARCHIVE_SITE_ID"] = self.site_id
        close_connection()
        init_db()
        if self._cm is not None:
            self._cm.__exit__(None, None, None)
        from app.main import app

        self._cm = TestClient(app)
        self.client = self._cm.__enter__()
        return self

    def close(self):
        if self._cm is not None:
            self._cm.__exit__(None, None, None)
            self._cm = None

    def bootstrap(self):
        self.activate()
        response = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": ADMIN_PASSWORD, "display_name": "站点主管", "client_label": "tests"},
        )
        assert response.status_code == 201, response.text
        login = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD, "client_label": "tests"},
        )
        assert login.status_code == 200, login.text
        self.headers = {"Authorization": f"Bearer {login.json()['token']}"}
        return self

    def post(self, path, payload):
        response = self.client.post(path, headers=self.headers, json=payload)
        return response

    def get(self, path):
        return self.client.get(path, headers=self.headers)

    def create_vault(self, code, sensitivity="normal"):
        response = self.post(
            "/api/dossiers/vaults",
            {
                "code": code,
                "building": "档案楼",
                "room": "常温库",
                "cabinet": "一号柜",
                "shelf": "一层",
                "sensitivity": sensitivity,
                "capacity_units": 100,
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    def create_batch(self, intake_code, project_code="PRJ"):
        response = self.post(
            "/api/dossiers/batches",
            {"intake_code": intake_code, "project_code": project_code, "expected_count": 5},
        )
        assert response.status_code == 201, response.text
        return response.json()

    def create_dossier(self, dossier_code, intake_id, quantity=10, vault_id=None, asset_type="工艺文档"):
        response = self.post(
            "/api/dossiers",
            {
                "dossier_code": dossier_code,
                "intake_id": intake_id,
                "asset_type": asset_type,
                "quantity": quantity,
                "unit": "份",
                "vault_id": vault_id,
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    def create_approver(self, username):
        response = self.post(
            "/api/users",
            {
                "username": username,
                "password": "Approver!234",
                "display_name": f"审批人{username}",
                "role_codes": ["approver"],
            },
        )
        assert response.status_code == 201, response.text
        login = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": "Approver!234", "client_label": "tests"},
        )
        assert login.status_code == 200, login.text
        return {"Authorization": f"Bearer {login.json()['token']}"}

    def export(self, since=None):
        response = self.post("/api/offline-packages/export", {"since_package_code": since})
        assert response.status_code == 201, response.text
        return response.json()


@pytest.fixture()
def sites(tmp_path):
    Site._all = []
    branch = Site(tmp_path / "branch.db", "BRANCH-A")
    hq = Site(tmp_path / "hq.db", "HQ")
    yield branch, hq
    for site in Site._all:
        site.close()
    Site._all = []
    os.environ.pop("ARCHIVE_SITE_ID", None)
    os.environ.pop("ARCHIVE_PACKAGE_KEY", None)


def _document_only(exported: dict) -> dict:
    """从导出响应中提取可传输的包文档（去掉本地管理字段）。"""
    return {key: exported[key] for key in (
        "package_code", "origin_site", "sequence", "parent_package_code", "parent_digest",
        "created_at", "items", "payload_digest", "package_digest", "signature",
    ) if key in exported}


def _prepare_branch_package(branch: Site):
    """分支站点产生一批新增档案、审批结果与载体变更，并导出离线包。"""
    branch.bootstrap()
    vault_one = branch.create_vault("BR-VAULT-01")
    vault_two = branch.create_vault("BR-VAULT-02")
    batch = branch.create_batch("BR-INTAKE-001")
    dossier = branch.create_dossier("BR-DOS-001", batch["id"], quantity=12, vault_id=vault_one["id"])
    moved = branch.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        {"vault_id": vault_two["id"], "expected_version": dossier["version"], "reason": "转入恒温库"},
    )
    assert moved.status_code == 200, moved.text
    approval = branch.post(
        "/api/dossiers/approvals",
        {
            "request_code": "BR-APR-001",
            "action_type": "disposal",
            "resource_type": "dossier",
            "resource_id": dossier["id"],
            "payload": {"quantity": 2},
        },
    )
    assert approval.status_code == 201, approval.text
    for username in ("approver.one", "approver.two"):
        headers = branch.create_approver(username)
        decided = branch.client.post(
            f"/api/dossiers/approvals/{approval.json()['id']}/decisions",
            headers=headers,
            json={"decision": "approve", "comment": "同意"},
        )
        assert decided.status_code == 200, decided.text
    return branch.export()


def _prepare_hq(hq: Site):
    hq.bootstrap()
    hq.create_vault("BR-VAULT-01")
    hq.create_vault("BR-VAULT-02")


def test_export_import_round_trip(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    assert document["package_code"] == "BRANCH-A-PKG-000001"
    assert document["sequence"] == 1
    assert document["parent_package_code"] is None
    assert [item["type"] for item in document["items"]] == [
        "intake_batch", "dossier_register", "approval_result", "vault_transfer",
    ]

    _prepare_hq(hq)
    preview = hq.post("/api/offline-packages/preview", {"document": document})
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    assert plan["valid"] is True
    assert plan["missing_dependencies"] == []
    assert all(item["action"] == "apply" for item in plan["items"])

    imported = hq.post("/api/offline-packages/import", {"document": document})
    assert imported.status_code == 201, imported.text
    result = imported.json()
    assert result["status"] == "committed"
    assert result["applied"] == 4
    assert result["failed"] == 0

    dossiers = hq.get("/api/dossiers").json()
    assert len(dossiers) == 1
    synced = dossiers[0]
    assert synced["dossier_code"] == "BR-DOS-001"
    assert synced["quantity"] == 12
    assert synced["vault_code"] == "BR-VAULT-02"
    assert synced["version"] == 2

    detail = hq.get(f"/api/dossiers/{synced['id']}").json()
    event_types = [event["event_type"] for event in detail["events"]]
    assert event_types == ["received", "vault.transferred"]
    assert all(event["correlation_id"] == "BRANCH-A-PKG-000001" for event in detail["events"])

    # 审计链：每个已应用条目都有对应的离线导入审计事件
    audits = hq.get("/api/audit?size=100").json()["data"]
    import_actions = {row["action"] for row in audits if row["correlation_id"] == "BRANCH-A-PKG-000001"}
    assert {
        "offline.import.intake_batch",
        "offline.import.dossier_register",
        "offline.import.approval_result",
        "offline.import.vault_transfer",
    } <= import_actions

    # 审批结果同步：请求与两条审批决定都在，结论为 approved
    connection = sqlite3.connect(hq.path)
    try:
        request = connection.execute(
            "SELECT * FROM approval_requests WHERE request_code='BR-APR-001'"
        ).fetchone()
        assert request is not None
        assert request[7] == "approved"  # state 列
        decision_count = connection.execute(
            "SELECT COUNT(*) FROM approval_decisions WHERE request_id=?", (request[0],)
        ).fetchone()[0]
        assert decision_count == 2
        # 分支审批人被映射为不可登录的影子账号，身份仍可核对
        approvers = connection.execute(
            "SELECT DISTINCT u.username FROM approval_decisions d JOIN users u ON u.id=d.approver_user_id WHERE d.request_id=?",
            (request[0],),
        ).fetchall()
        assert {row[0] for row in approvers} == {"off.branch-a.approver.one", "off.branch-a.approver.two"}
    finally:
        connection.close()

    verify = hq.get(f"/api/offline-packages/{result['package_id']}/verify")
    assert verify.status_code == 200, verify.text
    report = verify.json()
    assert report["ok"] is True, json.dumps(report, ensure_ascii=False)
    assert all(check["ok"] for check in report["checks"])


def test_import_is_idempotent_and_returns_original_result(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)

    first = hq.post("/api/offline-packages/import", {"document": document}).json()
    second = hq.post("/api/offline-packages/import", {"document": document})
    assert second.status_code == 201
    replay = second.json()
    assert replay["replayed"] is True
    assert replay["package_id"] == first["package_id"]
    assert replay["applied"] == first["applied"]
    assert replay["committed_at"] == first["committed_at"]

    # 没有重复写入：档案、审批、包都只有一份
    assert len(hq.get("/api/dossiers").json()) == 1
    packages = hq.get("/api/offline-packages").json()
    assert len(packages) == 1
    commit_again = hq.post(f"/api/offline-packages/{first['package_id']}/commit", {})
    assert commit_again.json()["replayed"] is True
    assert len(hq.get("/api/dossiers").json()) == 1


def test_preview_reports_missing_dependencies_without_writing(sites):
    _, hq = sites
    _prepare_hq(hq)
    document = build_package_document(
        package_code="BRANCH-A-PKG-000002",
        origin_site="BRANCH-A",
        sequence=2,
        parent_package_code="BRANCH-A-PKG-000001",
        parent_digest="0" * 64,
        created_at="2026-09-26T08:00:00+00:00",
        items=[
            {
                "index": 0,
                "type": "dossier_register",
                "key": "dossier_register:BR-DOS-900",
                "payload": {
                    "dossier_code": "BR-DOS-900",
                    "intake_code": "BR-INTAKE-900",
                    "asset_type": "工艺文档",
                    "quantity": 3,
                    "unit": "份",
                    "vault_code": "BR-VAULT-09",
                    "custody_user": None,
                    "occurred_at": "2026-09-26T08:00:00+00:00",
                },
            },
            {
                "index": 1,
                "type": "vault_transfer",
                "key": "vault_transfer:TRF-X",
                "payload": {
                    "dossier_code": "BR-DOS-404",
                    "to_vault_code": "BR-VAULT-01",
                    "base_version": 2,
                    "transfer_code": "TRF-X",
                    "reason": "调拨",
                    "occurred_at": "2026-09-26T09:00:00+00:00",
                },
            },
        ],
    )
    preview = hq.post("/api/offline-packages/preview", {"document": document})
    assert preview.status_code == 200, preview.text
    plan = preview.json()
    assert plan["valid"] is False
    kinds = {item["kind"] for item in plan["missing_dependencies"]}
    assert {"parent_package", "intake_batch", "vault", "dossier"} <= kinds
    blocked = [item for item in plan["items"] if item["action"] == "blocked"]
    assert len(blocked) == 2
    # 预演不落库
    assert hq.get("/api/offline-packages").json() == []


def test_out_of_order_package_fails_then_resumes(sites):
    branch, hq = sites
    branch.bootstrap()
    vault_one = branch.create_vault("BR-VAULT-01")
    vault_two = branch.create_vault("BR-VAULT-02")
    batch = branch.create_batch("BR-INTAKE-001")
    dossier = branch.create_dossier("BR-DOS-001", batch["id"], quantity=5, vault_id=vault_one["id"])
    package_one = _document_only(branch.export())
    moved = branch.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        {"vault_id": vault_two["id"], "expected_version": dossier["version"], "reason": "调拨"},
    )
    assert moved.status_code == 200, moved.text
    package_two = _document_only(branch.export())
    assert package_two["parent_package_code"] == package_one["package_code"]
    assert package_two["parent_digest"] == package_one["package_digest"]

    _prepare_hq(hq)
    # 先到的是 2 号包：父包缺失 → 失败但已登记，可稍后继续
    early = hq.post("/api/offline-packages/import", {"document": package_two})
    assert early.status_code == 201
    early_result = early.json()
    assert early_result["status"] == "failed"
    assert early_result["missing_dependencies"][0]["kind"] == "parent_package"
    assert hq.get("/api/dossiers").json() == []

    # 前置包到达后，断点续传成功
    first = hq.post("/api/offline-packages/import", {"document": package_one}).json()
    assert first["status"] == "committed"
    resumed = hq.post(f"/api/offline-packages/{early_result['package_id']}/commit", {})
    assert resumed.status_code == 200, resumed.text
    resumed_result = resumed.json()
    assert resumed_result["status"] == "committed"
    assert resumed_result["resumed"] is True
    dossier_after = hq.get("/api/dossiers").json()[0]
    assert dossier_after["vault_code"] == "BR-VAULT-02"
    assert dossier_after["version"] == 2

    verify = hq.get(f"/api/offline-packages/{resumed_result['package_id']}/verify").json()
    assert verify["ok"] is True, json.dumps(verify, ensure_ascii=False)


def test_version_fork_keeps_both_sources_and_resolves_keep_local(sites):
    branch, hq = sites
    branch.bootstrap()
    vault_one = branch.create_vault("BR-VAULT-01")
    vault_two = branch.create_vault("BR-VAULT-02")
    batch = branch.create_batch("BR-INTAKE-001")
    dossier = branch.create_dossier("BR-DOS-001", batch["id"], quantity=5, vault_id=vault_one["id"])
    package_one = _document_only(branch.export())
    moved = branch.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        {"vault_id": vault_two["id"], "expected_version": 1, "reason": "分支调拨"},
    )
    assert moved.status_code == 200, moved.text
    package_two = _document_only(branch.export())

    hq.bootstrap()
    hq.create_vault("BR-VAULT-01")
    hq.create_vault("BR-VAULT-02")
    hq_vault_three = hq.create_vault("HQ-VAULT-03")
    imported = hq.post("/api/offline-packages/import", {"document": package_one}).json()
    assert imported["status"] == "committed"
    hq_dossier = hq.get("/api/dossiers").json()[0]
    # 总部在收到分支变更前，独立把档案调拨到 HQ-VAULT-03 → 版本分叉
    local_move = hq.post(
        f"/api/dossier-operations/{hq_dossier['id']}/transfers",
        {"vault_id": hq_vault_three["id"], "expected_version": hq_dossier["version"], "reason": "总部本地调拨"},
    )
    assert local_move.status_code == 200, local_move.text

    conflicted = hq.post("/api/offline-packages/import", {"document": package_two}).json()
    assert conflicted["status"] == "committed"
    assert len(conflicted["conflicts"]) == 1
    fork_code = conflicted["conflicts"][0]["fork_code"]

    forks = hq.get("/api/offline-packages/forks?state=pending").json()
    assert len(forks) == 1
    fork = forks[0]
    assert fork["fork_code"] == fork_code
    assert fork["reason"] == "version_fork"
    # 两条来源都保留：本地快照与远端载荷
    assert fork["local_snapshot"]["vault_code"] == "HQ-VAULT-03"
    assert fork["incoming_payload"]["to_vault_code"] == "BR-VAULT-02"

    # 分叉未裁决前，独立核对的 forks 检查不通过
    report = hq.get(f"/api/offline-packages/{conflicted['package_id']}/verify").json()
    assert report["ok"] is False
    fork_check = next(check for check in report["checks"] if check["name"] == "forks")
    assert fork_check["ok"] is False

    resolved = hq.post(
        f"/api/offline-packages/forks/{fork['id']}/resolve",
        {"resolution": "keep_local", "note": "保留总部库位"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["state"] == "resolved_local"
    stayed = hq.get("/api/dossiers").json()[0]
    assert stayed["vault_code"] == "HQ-VAULT-03"

    report_after = hq.get(f"/api/offline-packages/{conflicted['package_id']}/verify").json()
    assert report_after["ok"] is True, json.dumps(report_after, ensure_ascii=False)


def test_version_fork_resolves_apply_remote(sites):
    branch, hq = sites
    branch.bootstrap()
    vault_one = branch.create_vault("BR-VAULT-01")
    vault_two = branch.create_vault("BR-VAULT-02")
    batch = branch.create_batch("BR-INTAKE-001")
    dossier = branch.create_dossier("BR-DOS-001", batch["id"], quantity=5, vault_id=vault_one["id"])
    package_one = _document_only(branch.export())
    moved = branch.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        {"vault_id": vault_two["id"], "expected_version": 1, "reason": "分支调拨"},
    )
    assert moved.status_code == 200
    package_two = _document_only(branch.export())

    hq.bootstrap()
    hq.create_vault("BR-VAULT-01")
    hq.create_vault("BR-VAULT-02")
    hq_vault_three = hq.create_vault("HQ-VAULT-03")
    hq.post("/api/offline-packages/import", {"document": package_one})
    hq_dossier = hq.get("/api/dossiers").json()[0]
    hq.post(
        f"/api/dossier-operations/{hq_dossier['id']}/transfers",
        {"vault_id": hq_vault_three["id"], "expected_version": hq_dossier["version"], "reason": "总部本地调拨"},
    )
    conflicted = hq.post("/api/offline-packages/import", {"document": package_two}).json()
    fork = hq.get("/api/offline-packages/forks?state=pending").json()[0]

    resolved = hq.post(
        f"/api/offline-packages/forks/{fork['id']}/resolve",
        {"resolution": "apply_remote", "note": "采用分支调拨"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["state"] == "resolved_remote"
    current = hq.get("/api/dossiers").json()[0]
    assert current["vault_code"] == "BR-VAULT-02"
    detail = hq.get(f"/api/dossiers/{current['id']}").json()
    forced = [event for event in detail["events"] if event["details"].get("fork_code") == fork["fork_code"]]
    assert forced and forced[0]["details"]["forced"] is True

    # 已裁决的分叉不能重复裁决
    again = hq.post(
        f"/api/offline-packages/forks/{fork['id']}/resolve",
        {"resolution": "keep_local", "note": "重复裁决"},
    )
    assert again.status_code == 409


def test_register_conflict_goes_to_adjudication(sites):
    branch, hq = sites
    branch.bootstrap()
    vault = branch.create_vault("BR-VAULT-01")
    batch = branch.create_batch("BR-INTAKE-001")
    branch.create_dossier("SHARED-001", batch["id"], quantity=10, vault_id=vault["id"])
    document = _document_only(branch.export())

    hq.bootstrap()
    hq.create_vault("BR-VAULT-01")
    hq_batch = hq.create_batch("HQ-INTAKE-001")
    hq.create_dossier("SHARED-001", hq_batch["id"], quantity=99, vault_id=None)

    result = hq.post("/api/offline-packages/import", {"document": document}).json()
    assert result["status"] == "committed"
    register_item = next(item for item in result["items"] if item["type"] == "dossier_register")
    assert register_item["status"] == "conflict"
    fork = hq.get("/api/offline-packages/forks?state=pending").json()[0]
    assert fork["reason"] == "register_conflict"
    assert fork["local_snapshot"]["quantity"] == 99
    assert fork["incoming_payload"]["quantity"] == 10
    # 本地内容未被覆盖
    assert hq.get("/api/dossiers").json()[0]["quantity"] == 99


def test_tampered_package_is_rejected(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)
    tampered = json.loads(json.dumps(document))
    tampered["items"][1]["payload"]["quantity"] = 999
    response = hq.post("/api/offline-packages/import", {"document": tampered})
    assert response.status_code == 422
    assert "摘要" in response.json()["error"]["message"]
    assert hq.get("/api/offline-packages").json() == []


def test_cli_import_and_verify(sites, tmp_path):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)
    package_file = tmp_path / "package.json"
    package_file.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    env = {
        **os.environ,
        "ARCHIVE_DATABASE_PATH": str(hq.path),
        "ARCHIVE_SITE_ID": "HQ",
        "PYTHONPATH": "/workspace",
    }
    imported = subprocess.run(
        [sys.executable, "-m", "app.cli", "import-package", str(package_file)],
        capture_output=True,
        text=True,
        env=env,
        cwd="/workspace",
    )
    assert imported.returncode == 0, imported.stderr + imported.stdout
    result = json.loads(imported.stdout)
    assert result["status"] == "committed"

    verified = subprocess.run(
        [sys.executable, "-m", "app.cli", "verify-package", document["package_code"]],
        capture_output=True,
        text=True,
        env=env,
        cwd="/workspace",
    )
    assert verified.returncode == 0, verified.stderr + verified.stdout
    report = json.loads(verified.stdout)
    assert report["ok"] is True

    # 总部数据库里确实写入了档案
    dossiers = hq.get("/api/dossiers").json()
    assert len(dossiers) == 1


def test_item_level_failure_resumes_after_dependency_arrives(sites):
    branch, hq = sites
    branch.bootstrap()
    vault = branch.create_vault("BR-VAULT-01")
    batch = branch.create_batch("BR-INTAKE-001")
    branch.create_dossier("BR-DOS-001", batch["id"], quantity=5, vault_id=vault["id"])
    document = _document_only(branch.export())

    # 总部尚未建库位：条目级缺失依赖 → 包失败但已登记
    hq.bootstrap()
    first = hq.post("/api/offline-packages/import", {"document": document}).json()
    assert first["status"] == "failed"
    assert first["missing_dependencies"][0]["kind"] == "vault"
    failed_item = next(item for item in first["items"] if item["status"] == "failed")
    assert failed_item["type"] == "dossier_register"
    # 已应用的批次条目被保留（分阶段提交，不会整体回滚）
    intake_item = next(item for item in first["items"] if item["type"] == "intake_batch")
    assert intake_item["status"] == "applied"

    # 网络恢复后同一包被重传：从失败点继续，不重复写入已应用条目
    hq.create_vault("BR-VAULT-01")
    second = hq.post("/api/offline-packages/import", {"document": document}).json()
    assert second["status"] == "committed"
    assert second["resumed"] is True
    resumed_intake = next(item for item in second["items"] if item["type"] == "intake_batch")
    assert resumed_intake["status"] == "applied"
    assert len(hq.get("/api/dossiers").json()) == 1
    batches = hq.get("/api/dossier-operations/batches/open").json()
    assert len([batch for batch in batches if batch["intake_code"] == "BR-INTAKE-001"]) == 1


def test_verification_detects_storage_tampering(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)
    result = hq.post("/api/offline-packages/import", {"document": document}).json()
    assert result["status"] == "committed"
    assert hq.get(f"/api/offline-packages/{result['package_id']}/verify").json()["ok"] is True

    # 直接篡改库里暂存的条目载荷：独立核对必须能发现摘要不再匹配
    connection = sqlite3.connect(hq.path)
    try:
        connection.execute(
            "UPDATE offline_package_items SET payload_json=REPLACE(payload_json, '\"quantity\":12', '\"quantity\":13') "
            "WHERE item_type='dossier_register'"
        )
        connection.commit()
    finally:
        connection.close()
    report = hq.get(f"/api/offline-packages/{result['package_id']}/verify").json()
    assert report["ok"] is False
    digest_check = next(check for check in report["checks"] if check["name"] == "digests")
    assert digest_check["ok"] is False


def test_same_code_different_digest_is_rejected(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)
    assert hq.post("/api/offline-packages/import", {"document": document}).json()["status"] == "committed"

    # 同一来源、同一包编号但内容不同（摘要不同）→ 拒绝，防止覆盖已导入批次
    forged = build_package_document(
        package_code=document["package_code"],
        origin_site=document["origin_site"],
        sequence=document["sequence"],
        parent_package_code=None,
        parent_digest=None,
        created_at="2026-09-26T10:00:00+00:00",
        items=[],
    )
    assert forged["package_digest"] != document["package_digest"]
    response = hq.post("/api/offline-packages/import", {"document": forged})
    assert response.status_code == 409


def test_signed_package_round_trip_and_tamper_detection(sites, monkeypatch):
    monkeypatch.setenv("ARCHIVE_PACKAGE_KEY", "shared-secret")
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    assert "signature" in document
    _prepare_hq(hq)
    monkeypatch.setenv("ARCHIVE_PACKAGE_KEY", "shared-secret")
    imported = hq.post("/api/offline-packages/import", {"document": document})
    assert imported.status_code == 201, imported.text
    assert imported.json()["status"] == "committed"

    verify = hq.get(f"/api/offline-packages/{imported.json()['package_id']}/verify").json()
    signature_check = next(check for check in verify["checks"] if check["name"] == "signature")
    assert signature_check["ok"] is True

    # 错误密钥下签名不被接受
    monkeypatch.setenv("ARCHIVE_PACKAGE_KEY", "wrong-secret")
    hq2 = Site(hq.path.parent / "hq2.db", "HQ").bootstrap()
    hq2.create_vault("BR-VAULT-01")
    hq2.create_vault("BR-VAULT-02")
    rejected = hq2.post("/api/offline-packages/import", {"document": document})
    assert rejected.status_code == 422


def test_permissions_are_enforced(sites):
    branch, hq = sites
    document = _document_only(_prepare_branch_package(branch))
    _prepare_hq(hq)
    researcher = hq.create_approver("researcher.one")
    # approver 角色没有 offline_packages.manage，不能导入
    denied = hq.client.post(
        "/api/offline-packages/import",
        headers=researcher,
        json={"document": document},
    )
    assert denied.status_code == 403
    # 未认证直接拒绝
    anonymous = hq.client.post("/api/offline-packages/import", json={"document": document})
    assert anonymous.status_code == 401
