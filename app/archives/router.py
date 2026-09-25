from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.schemas import (
    CopyIssueRequest,
    IncidentCreate,
    ApprovalCreate,
    ApprovalDecision,
    BatchCreate,
    DisclosureUseCreate,
    LoanCreate,
    LoanReturn,
    LocationCreate,
    DossierCreate,
)
from app.archives.service import IncidentService, ApprovalService, AccessLoanService, VaultService, DossierLifecycleService

router = APIRouter(prefix="/api/dossiers", tags=["知识产权档案"])


@router.post("/vaults", status_code=status.HTTP_201_CREATED)
def create_vault(payload: LocationCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return VaultService(connection).create(principal, payload.model_dump())


@router.get("/vaults")
def list_vaults(principal: Principal = Depends(current_principal)):
    return VaultService(get_connection()).list(principal)


@router.post("/batches", status_code=status.HTTP_201_CREATED)
def create_batch(payload: BatchCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).create_batch(principal, payload.model_dump())


@router.post("", status_code=status.HTTP_201_CREATED)
def create_dossier(payload: DossierCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).register_dossier(principal, payload.model_dump())


@router.get("")
def list_dossiers(
    lifecycle_state: str | None = Query(default=None),
    intake_id: int | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return DossierLifecycleService(get_connection()).list_dossiers(principal, lifecycle_state, intake_id)


@router.get("/{dossier_id}")
def get_dossier(dossier_id: int, principal: Principal = Depends(current_principal)):
    return DossierLifecycleService(get_connection()).detail(principal, dossier_id)


@router.post("/{dossier_id}/issue_copys", status_code=status.HTTP_201_CREATED)
def issue_copy(dossier_id: int, payload: CopyIssueRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).issue_copy(principal, dossier_id, payload.model_dump())


@router.post("/{dossier_id}/disclosures", status_code=status.HTTP_201_CREATED)
def disclose(dossier_id: int, payload: DisclosureUseCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).disclose(principal, dossier_id, payload.model_dump())


@router.post("/access_loans", status_code=status.HTTP_201_CREATED)
def create_access_loan(payload: LoanCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessLoanService(connection).create(principal, payload.model_dump())


@router.post("/access_loans/{access_loan_id}/returns")
def return_access_loan(access_loan_id: int, payload: LoanReturn, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessLoanService(connection).return_access_loan(principal, access_loan_id, payload.model_dump())


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
def create_approval(payload: ApprovalCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ApprovalService(connection).create(principal, payload.model_dump())


@router.post("/approvals/{request_id}/decisions")
def decide_approval(request_id: int, payload: ApprovalDecision, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ApprovalService(connection).decide(principal, request_id, payload.model_dump())


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentService(connection).create(principal, payload.model_dump())


@router.get("/incidents/list")
def list_incidents(state: str | None = None, principal: Principal = Depends(current_principal)):
    return IncidentService(get_connection()).list(principal, state)
