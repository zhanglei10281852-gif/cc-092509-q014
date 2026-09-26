from __future__ import annotations

import argparse
import json

from fastapi.testclient import TestClient

from app.core.security import Principal
from app.database import database_path, get_connection, init_db


def command_init() -> None:
    init_db()
    print(json.dumps({"database": str(database_path()), "initialized": True}, ensure_ascii=False))


def command_check() -> None:
    init_db()
    connection = get_connection()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    print(json.dumps({"integrity": integrity, "foreign_keys": foreign_keys, "journal_mode": journal_mode}, ensure_ascii=False))
    if integrity != "ok" or foreign_keys != 1:
        raise SystemExit(1)


def command_smoke() -> None:
    from app.main import app

    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
        print(json.dumps({"root": root.status_code, "health": health.status_code, "service": root.json().get("service")}, ensure_ascii=False))
        if root.status_code != 200 or health.status_code != 200:
            raise SystemExit(1)


def _offline_principal() -> Principal:
    """离线命令行的系统身份：拥有全部权限，审计 actor 为空用户。"""
    return Principal(
        user_id=None,  # type: ignore[arg-type]
        username="offline-cli",
        display_name="离线命令行",
        department_id=None,
        permissions=frozenset({"*"}),
        session_id=0,
    )


def command_import_package(package_file: str) -> None:
    from app.archives.offline import OfflineImportService
    from app.core.errors import DomainError

    init_db()
    with open(package_file, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    service = OfflineImportService(get_connection())
    try:
        result = service.import_package(_offline_principal(), document)
    except DomainError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}}, ensure_ascii=False))
        raise SystemExit(1)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") != "committed":
        raise SystemExit(1)


def command_verify_package(package_code: str) -> None:
    from app.archives.offline import OfflineVerificationService
    from app.core.errors import DomainError

    init_db()
    service = OfflineVerificationService(get_connection())
    try:
        report = service.verify_by_code(_offline_principal(), package_code)
    except DomainError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}}, ensure_ascii=False))
        raise SystemExit(1)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report.get("ok"):
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="知识产权档案服务维护命令")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="API 冒烟检查")
    import_parser = subparsers.add_parser("import-package", help="离线导入移交包（登记并分阶段提交，可断点续传）")
    import_parser.add_argument("package_file", help="移交包 JSON 文件路径")
    verify_parser = subparsers.add_parser("verify-package", help="独立核对离线包摘要链、审计链与当前有效状态")
    verify_parser.add_argument("package_code", help="移交包编号")
    args = parser.parse_args()
    if args.command == "init-db":
        command_init()
    elif args.command == "check-db":
        command_check()
    elif args.command == "smoke":
        command_smoke()
    elif args.command == "import-package":
        command_import_package(args.package_file)
    elif args.command == "verify-package":
        command_verify_package(args.package_code)


if __name__ == "__main__":
    main()
