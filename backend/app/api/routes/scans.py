from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.scanner import InvalidTarget, ScanNetworkError, scan as run_scan


router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"]
)


class ScanCreate(BaseModel):
    project_id: int


class ScanResponse(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


@router.post("/", response_model=ScanResponse)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == scan_data.project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    scan = Scan(
        project_id=scan_data.project_id,
        status="pending"
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Execute the bounded scanner synchronously so API clients see a terminal state.
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    target_url = project.target_url or "http://127.0.0.1:3000"
    db.commit()
    try:
        _, findings = run_scan(target_url)
        for item in findings:
            db.add(Finding(
                scan_id=scan.id,
                title=item.title,
                vulnerability_type=item.vulnerability_type,
                severity=item.severity,
                url=item.url,
                description=item.description,
                evidence=item.evidence,
                remediation=item.remediation,
                status="open",
            ))
        scan.status = "completed"
    except InvalidTarget as exc:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan.id).first()
        scan.status = "failed"
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScanNetworkError:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan.id).first()
        scan.status = "failed"
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=502, detail="Target scan failed")
    except Exception:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan.id).first()
        scan.status = "failed"
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
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

    return scan


@router.get(
    "/project/{project_id}",
    response_model=list[ScanResponse]
)
def get_project_scans(
    project_id: int,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    return db.query(Scan).filter(
        Scan.project_id == project_id
    ).all()
