from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.offline import (
    OfflineExportService,
    OfflineForkService,
    OfflineImportService,
    OfflinePackageRepository,
    OfflineVerificationService,
)
from app.archives.offline_schemas import ForkResolveRequest, OfflineExportRequest, OfflinePackageDocument

router = APIRouter(prefix="/api/offline-packages", tags=["离线移交包"])


@router.post("/export", status_code=status.HTTP_201_CREATED)
def export_package(payload: OfflineExportRequest, principal: Principal = Depends(current_principal)):
    """把上一导出包之后的新增档案、审批结果与载体变更打包，带父包指针与链式摘要。"""
    with transaction(immediate=True) as connection:
        return OfflineExportService(connection).export(principal, payload.since_package_code)


@router.post("/preview")
def preview_package(payload: OfflinePackageDocument, principal: Principal = Depends(current_principal)):
    """预演导入：不落库地校验摘要链并报告缺失依赖、分叉与每个条目的处置方式。"""
    return OfflineImportService(get_connection()).preview(principal, payload.document)


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_package(payload: OfflinePackageDocument, principal: Principal = Depends(current_principal)):
    """登记并分阶段提交离线包；同一包重复提交返回原批次结果，不重复写入。"""
    return OfflineImportService(get_connection()).import_package(principal, payload.document)


@router.get("")
def list_packages(
    origin_site: str | None = Query(default=None),
    status: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    principal.require("offline_packages.read")
    return OfflinePackageRepository(get_connection()).list(origin_site=origin_site, status=status, direction=direction)


@router.get("/forks")
def list_forks(state: str | None = Query(default=None), principal: Principal = Depends(current_principal)):
    return OfflineForkService(get_connection()).list(principal, state)


@router.post("/forks/{fork_id}/resolve")
def resolve_fork(fork_id: int, payload: ForkResolveRequest, principal: Principal = Depends(current_principal)):
    """人工裁决分叉：保留本地或采用远端；两条来源都保留在分叉记录中。"""
    with transaction(immediate=True) as connection:
        return OfflineForkService(connection).resolve(principal, fork_id, payload.resolution, payload.note)


@router.get("/{package_id}")
def package_detail(package_id: int, principal: Principal = Depends(current_principal)):
    principal.require("offline_packages.read")
    repository = OfflinePackageRepository(get_connection())
    package = repository.get(package_id)
    return {
        **package,
        "items": repository.items(package_id),
        "forks": repository.list_forks(package_id=package_id),
    }


@router.post("/{package_id}/commit")
def commit_package(package_id: int, principal: Principal = Depends(current_principal)):
    """提交已登记或失败的离线包；从第一个未完成条目继续，已提交包直接返回原批次结果。"""
    return OfflineImportService(get_connection()).commit(principal, package_id)


@router.get("/{package_id}/verify")
def verify_package(package_id: int, principal: Principal = Depends(current_principal)):
    """独立核对：重算摘要链与顺序，检查审计链、版本关系和当前有效状态。"""
    return OfflineVerificationService(get_connection()).verify(principal, package_id)
