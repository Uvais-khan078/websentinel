from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan


router = APIRouter(
    prefix="/api/findings",
    tags=["Findings"]
)


class FindingCreate(BaseModel):
    scan_id: int
    title: str
    vulnerability_type: str
    severity: str
    url: str
    parameter: str | None = None
    description: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    status: str = "open"


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    vulnerability_type: str
    severity: str
    url: str
    parameter: str | None
    description: str | None
    evidence: str | None
    remediation: str | None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=FindingResponse)
def create_finding(
    finding_data: FindingCreate,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == finding_data.scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    finding = Finding(
        scan_id=finding_data.scan_id,
        title=finding_data.title,
        vulnerability_type=finding_data.vulnerability_type,
        severity=finding_data.severity,
        url=finding_data.url,
        parameter=finding_data.parameter,
        description=finding_data.description,
        evidence=finding_data.evidence,
        remediation=finding_data.remediation,
        status=finding_data.status
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


@router.get(
    "/{finding_id}",
    response_model=FindingResponse
)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(
        Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return finding


@router.get(
    "/scan/{scan_id}",
    response_model=list[FindingResponse]
)
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()
