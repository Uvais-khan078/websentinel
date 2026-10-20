from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.database import Base
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.scanner import InvalidTarget, ScanNetworkError, fetch_target, validate_target
from app.api.routes.scans import create_scan, ScanCreate

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Session = sessionmaker(autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def response(status=200, headers=None):
    return SimpleNamespace(status_code=status, headers=headers or {}, is_redirect=status in (301,302,303,307,308), is_permanent_redirect=status in (301,308), close=lambda: None)


def test_invalid_targets_rejected():
    for url in ("https://127.0.0.1:3000", "http://example.com:3000", "http://127.0.0.1:3001", "http://u:p@127.0.0.1:3000"):
        with pytest.raises(InvalidTarget):
            validate_target(url)


def test_redirect_destination_validated_before_request():
    with patch("app.services.scanner._resolve_all_loopback", return_value=True), patch("app.services.scanner.requests.Session") as factory:
        factory.return_value.get.return_value = response(302, {"Location": "http://example.com/"})
        with pytest.raises(InvalidTarget):
            fetch_target("http://127.0.0.1:3000/redirect")
        assert factory.return_value.get.call_count == 1


def test_network_failure_not_a_finding():
    from requests.exceptions import ConnectionError
    with patch("app.services.scanner._resolve_all_loopback", return_value=True), patch("app.services.scanner.requests.Session") as factory:
        factory.return_value.get.side_effect = ConnectionError("offline")
        with pytest.raises(ScanNetworkError):
            fetch_target("http://127.0.0.1:3000")


def test_scan_lifecycle_and_findings_persist_and_retrieve():
    with Session() as db:
        project = Project(name="lab", target_url="http://127.0.0.1:3000")
        db.add(project); db.commit(); db.refresh(project)
        with patch("app.api.routes.scans.run_scan") as scanner:
            scanner.return_value = (object(), [SimpleNamespace(title="Missing CSP", vulnerability_type="MissingSecurityHeader", severity="medium", url=project.target_url, description="No CSP", evidence="CSP absent", remediation="Set CSP")])
            scan = create_scan(ScanCreate(project_id=project.id), db)
        assert scan.status == "completed" and scan.started_at and scan.completed_at
        saved = db.query(Finding).filter_by(scan_id=scan.id).one()
        assert saved.evidence == "CSP absent" and saved.severity == "medium"
        assert db.query(Scan).filter_by(id=scan.id).one().status == "completed"


def test_invalid_project_target_marks_failed():
    with Session() as db:
        project = Project(name="out", target_url="http://example.com:3000")
        db.add(project); db.commit(); db.refresh(project)
        with pytest.raises(Exception):
            create_scan(ScanCreate(project_id=project.id), db)
        scan = db.query(Scan).one()
        assert scan.status == "failed" and scan.completed_at


def test_network_failure_marks_scan_failed_without_finding():
    with Session() as db:
        project = Project(name="offline", target_url="http://127.0.0.1:3000")
        db.add(project); db.commit(); db.refresh(project)
        with patch("app.api.routes.scans.run_scan", side_effect=ScanNetworkError("offline")):
            with pytest.raises(Exception):
                create_scan(ScanCreate(project_id=project.id), db)
        assert db.query(Scan).one().status == "failed"
        assert db.query(Finding).count() == 0
