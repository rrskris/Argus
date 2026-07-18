"""RBAC scan router — misconfiguration findings scored by the shared Contextual Risk Score engine."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_active_user
from ..rbac_service import diff_latest_scans, get_latest_rbac_scan, scan_rbac
from ..report_service import build_rbac_scan_pdf

router = APIRouter(prefix="/rbac", tags=["RBAC"])


@router.post("/scan")
def run_rbac_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Scan the live cluster's Roles, ClusterRoles, and bindings for
    misconfigurations (wildcard permissions, cluster-admin bound to broad
    identities, broad secrets access, exec/attach grants), scored by the
    same Contextual Risk Score engine CVE findings use.
    """
    return scan_rbac(db, user.tenant_id)


@router.get("/scan/latest")
def get_latest_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the most recent RBAC scan result."""
    result = get_latest_rbac_scan(db)
    if not result:
        return {"message": "No scan results yet. POST /rbac/scan to run the first scan."}
    return result


@router.get("/scan/diff")
def get_scan_diff(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return findings added, resolved, or unchanged since the previous scan."""
    return diff_latest_scans(db)


@router.get("/scan/latest/report.pdf")
def get_latest_scan_report_pdf(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Download the most recent RBAC scan as a PDF report."""
    scan = get_latest_rbac_scan(db)
    if not scan:
        raise HTTPException(404, "No scan results yet. Run a scan first.")
    pdf_bytes = build_rbac_scan_pdf(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=kaaval-rbac-report.pdf"},
    )
