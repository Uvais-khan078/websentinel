from fastapi import FastAPI

from app.database.database import Base, engine
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding

from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router
from app.api.routes.findings import router as findings_router
from fastapi.middleware.cors import CORSMiddleware

Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="WebSentinel API",
    description="AI-Assisted Web Application Penetration Testing Platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(projects_router)
app.include_router(scans_router)
app.include_router(findings_router)

@app.get("/")
def root():
    return {
        "project": "WebSentinel",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }