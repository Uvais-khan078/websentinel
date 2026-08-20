from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.project import Project


router = APIRouter(
    prefix="/api/projects",
    tags=["Projects"]
)


class ProjectCreate(BaseModel):
    name: str
    target_url: str
    description: str | None = None


class ProjectResponse(BaseModel):
    id: int
    name: str
    target_url: str
    description: str | None

    class Config:
        from_attributes = True


@router.post("/", response_model=ProjectResponse)
def create_project(
    project_data: ProjectCreate,
    db: Session = Depends(get_db)
):
    project = Project(
        name=project_data.name,
        target_url=project_data.target_url,
        description=project_data.description
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


@router.get("/", response_model=list[ProjectResponse])
def get_projects(
    db: Session = Depends(get_db)
):
    return db.query(Project).all()


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
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

    return project
