from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.extended_schemas import (
    DisclosureCreate,
    DisposalExecute,
    InventoryReviewCount,
    InventoryReviewStart,
    TransferCreate,
)
from app.archives.inventory_review import InventoryReviewService, ArchiveSummaryService
from app.archives.operations import DisclosureService, DisposalService, ProvenanceService, TransferService
from app.archives.reporting import BatchReconciliationService, ExceptionAgingService

router = APIRouter(prefix="/api/dossier-operations", tags=["档案作业"])


@router.post("/disclosures", status_code=status.HTTP_201_CREATED)
def register_collection(payload: DisclosureCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DisclosureService(connection).register(principal, payload.model_dump())


@router.post("/{dossier_id}/transfers")
def transfer_dossier(dossier_id: int, payload: TransferCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return TransferService(connection).move(principal, dossier_id, payload.model_dump())


@router.get("/{dossier_id}/provenance")
def dossier_provenance(dossier_id: int, principal: Principal = Depends(current_principal)):
    return ProvenanceService(get_connection()).graph(principal, dossier_id)


@router.post("/inventory_review", status_code=status.HTTP_201_CREATED)
def start_inventory_review(payload: InventoryReviewStart, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InventoryReviewService(connection).start(principal, payload.vault_id, payload.session_code)


@router.post("/inventory_review/{session_id}/counts")
def record_count(session_id: int, payload: InventoryReviewCount, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InventoryReviewService(connection).count(
            principal,
            session_id,
            payload.dossier_id,
            payload.observed_present,
            payload.observed_quantity,
            payload.note,
        )


@router.post("/inventory_review/{session_id}/reconcile")
def reconcile_inventory_review(session_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InventoryReviewService(connection).reconcile(principal, session_id)


@router.post("/inventory_review/{session_id}/close")
def close_inventory_review(session_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InventoryReviewService(connection).close_without_adjustment(principal, session_id)


@router.get("/stock/by-vault")
def stock_by_vault(principal: Principal = Depends(current_principal)):
    return ArchiveSummaryService(get_connection()).by_vault(principal)


@router.get("/stock/by-state")
def stock_by_state(principal: Principal = Depends(current_principal)):
    return ArchiveSummaryService(get_connection()).by_state(principal)


@router.post("/disposals/{request_id}", status_code=status.HTTP_201_CREATED)
def execute_disposal(
    request_id: int,
    payload: DisposalExecute,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        return DisposalService(connection).execute(principal, request_id, payload.model_dump())


@router.get("/batches/{intake_id}/reconciliation")
def batch_reconciliation(intake_id: int, principal: Principal = Depends(current_principal)):
    return BatchReconciliationService(get_connection()).detail(principal, intake_id)


@router.get("/batches/open")
def open_batches(principal: Principal = Depends(current_principal)):
    return BatchReconciliationService(get_connection()).open_batches(principal)


@router.get("/exceptions/aging")
def exception_aging(principal: Principal = Depends(current_principal)):
    return ExceptionAgingService(get_connection()).summary(principal)
