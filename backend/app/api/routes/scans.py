from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.project import Project
from app.models.scan import Scan


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

    class Config:
        from_attributes = True


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
