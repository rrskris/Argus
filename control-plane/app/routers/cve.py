"""CVE Feed router — manage feeds, run cluster scans, browse CVE entries."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_active_user
from ..models import CVEFeed, CVEEntry, ClusterRegistration, K8sCVEScanResult
from ..cve_service import cve_service, K8S_FEED_NAME, K8S_OFFICIAL_CVE_FEED_URL
from ..report_service import build_cve_scan_pdf

VALID_ENVIRONMENTS = {"production", "staging", "dev"}
VALID_DATA_CLASSIFICATIONS = {"public", "internal", "pii", "financial", "phi"}
VALID_EXPOSURES = {"internet-facing", "internal"}

router = APIRouter(prefix="/cve", tags=["CVE"])


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class FeedCreate(BaseModel):
    name: str
    url: str
    feed_type: str = "auto"          # auto | json_feed | osv | nvd
    description: Optional[str] = None


class ScanContextUpdate(BaseModel):
    environment: Optional[str] = None
    data_classification: Optional[str] = None
    compliance_scope: Optional[list[str]] = None
    exposure: Optional[str] = None


# ── Feed management ────────────────────────────────────────────────────────────

@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db), user=Depends(get_current_active_user)):
    """List all configured CVE feeds."""
    feeds = db.query(CVEFeed).order_by(CVEFeed.created_at).all()
    return [
        {
            "id": str(f.id),
            "name": f.name,
            "url": f.url,
            "feed_type": f.feed_type,
            "description": f.description,
            "enabled": f.enabled,
            "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
            "entry_count": f.entry_count,
        }
        for f in feeds
    ]


@router.post("/feeds", status_code=201)
def add_feed(
    body: FeedCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Add a new CVE feed (Kubernetes official, OSV, NVD, or any compatible JSON endpoint)."""
    if db.query(CVEFeed).filter(CVEFeed.name == body.name).first():
        raise HTTPException(400, f"A feed named '{body.name}' already exists.")
    feed = CVEFeed(
        name=body.name,
        url=body.url,
        feed_type=body.feed_type,
        description=body.description,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return {
        "id": str(feed.id),
        "name": feed.name,
        "message": "Feed added. POST /cve/feeds/{id}/refresh to load CVEs.",
    }


@router.delete("/feeds/{feed_id}")
def delete_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Delete a feed and all its CVE entries."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    db.delete(feed)
    db.commit()
    return {"message": f"Feed '{feed.name}' and all its entries deleted."}


@router.patch("/feeds/{feed_id}/toggle")
def toggle_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Enable or disable a feed without deleting it."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    feed.enabled = not feed.enabled
    db.commit()
    return {"id": str(feed.id), "name": feed.name, "enabled": feed.enabled}


@router.post("/feeds/{feed_id}/refresh")
async def refresh_feed(
    feed_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Fetch and reload CVE data for a single feed."""
    feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    try:
        return await cve_service.refresh_feed(feed_id, db)
    except Exception as e:
        raise HTTPException(502, f"Feed fetch failed: {e}")


@router.post("/feeds/refresh-all")
async def refresh_all_feeds(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Fetch and reload CVE data for all enabled feeds."""
    results = await cve_service.refresh_all_feeds(db)
    return {"results": results}


# ── CVE entry browser ──────────────────────────────────────────────────────────

@router.get("/entries")
def list_entries(
    severity: Optional[str] = None,
    feed_id: Optional[UUID] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Browse all CVE entries with optional filters."""
    q = db.query(CVEEntry).join(CVEFeed).filter(CVEFeed.enabled == True)
    if severity:
        q = q.filter(CVEEntry.severity == severity.upper())
    if feed_id:
        q = q.filter(CVEEntry.feed_id == feed_id)
    if search:
        pattern = f"%{search}%"
        q = q.filter(CVEEntry.cve_id.ilike(pattern) | CVEEntry.title.ilike(pattern))

    total = q.count()
    entries = q.order_by(CVEEntry.published_date.desc().nullslast()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": [
            {
                "id": str(e.id),
                "feed_id": str(e.feed_id),
                "cve_id": e.cve_id,
                "title": e.title,
                "severity": e.severity,
                "cvss_score": e.cvss_score,
                "published_date": e.published_date.isoformat() if e.published_date else None,
                "affected_components": e.affected_components,
                "fixed_in": e.fixed_in,
                "references": (e.references or [])[:3],
            }
            for e in entries
        ],
    }


# ── Risk context (drives the Contextual Risk Score) ───────────────────────────

def _context_response(context) -> dict:
    return {
        "environment": context.environment,
        "data_classification": context.data_classification,
        "compliance_scope": context.compliance_scope or [],
        "exposure": context.exposure,
        "updated_at": context.updated_at.isoformat() if context.updated_at else None,
    }


@router.get("/context")
def get_scan_context(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Return this tenant's risk context — environment, data classification,
    compliance scope, and exposure — used to compute the Contextual Risk
    Score for every finding. Auto-creates sensible defaults on first access.
    """
    context = cve_service.get_or_create_scan_context(db, user.tenant_id)
    return _context_response(context)


@router.put("/context")
def update_scan_context(
    body: ScanContextUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Update the tenant's risk context. Only provided fields are changed."""
    if body.environment is not None and body.environment not in VALID_ENVIRONMENTS:
        raise HTTPException(400, f"environment must be one of {sorted(VALID_ENVIRONMENTS)}")
    if body.data_classification is not None and body.data_classification not in VALID_DATA_CLASSIFICATIONS:
        raise HTTPException(400, f"data_classification must be one of {sorted(VALID_DATA_CLASSIFICATIONS)}")
    if body.exposure is not None and body.exposure not in VALID_EXPOSURES:
        raise HTTPException(400, f"exposure must be one of {sorted(VALID_EXPOSURES)}")

    context = cve_service.get_or_create_scan_context(db, user.tenant_id)
    if body.environment is not None:
        context.environment = body.environment
    if body.data_classification is not None:
        context.data_classification = body.data_classification
    if body.compliance_scope is not None:
        context.compliance_scope = body.compliance_scope
    if body.exposure is not None:
        context.exposure = body.exposure
    db.commit()
    db.refresh(context)
    return _context_response(context)


# ── Cluster scan ───────────────────────────────────────────────────────────────

@router.post("/scan")
def run_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Scan the live cluster against all CVEs in enabled feeds."""
    return cve_service.scan_cluster(db, user.tenant_id)


@router.get("/scan/latest")
def get_latest_scan(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the most recent cluster scan result."""
    result = cve_service.get_latest_scan(db)
    if not result:
        return {"message": "No scan results yet. POST /cve/scan to run the first scan."}
    return result


@router.get("/scan/latest/report.pdf")
def get_latest_scan_report_pdf(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Download the most recent cluster scan as a PDF report."""
    scan = cve_service.get_latest_scan(db)
    if not scan:
        raise HTTPException(404, "No scan results yet. Run a scan first.")
    pdf_bytes = build_cve_scan_pdf(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=argus-cve-report.pdf"},
    )


# ── Summary ────────────────────────────────────────────────────────────────────

@router.get("/summary")
def get_summary(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Quick dashboard summary: feed stats, total CVE count, severity breakdown, latest scan."""
    feeds = db.query(CVEFeed).all()
    total_entries = db.query(CVEEntry).count()
    severity_counts = {
        sev: db.query(CVEEntry).filter(CVEEntry.severity == sev).count()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    }
    return {
        "feeds": len(feeds),
        "total_cves": total_entries,
        "severity_breakdown": severity_counts,
        "latest_scan": cve_service.get_latest_scan(db),
    }


# ── Kubernetes official CVE feed ───────────────────────────────────────────────

@router.post("/k8s/feed/sync", status_code=200)
async def sync_k8s_feed(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Ensure the official Kubernetes CVE feed is registered, then fetch/refresh it.
    Safe to call repeatedly — creates the feed entry once, refreshes on every call.
    """
    feed = await cve_service.ensure_k8s_feed(db)
    try:
        result = await cve_service.refresh_feed(feed.id, db)
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch K8s CVE feed: {e}")
    return {
        "feed_id": str(feed.id),
        "feed_name": feed.name,
        "feed_url": feed.url,
        **result,
    }


@router.get("/k8s/feed")
async def get_k8s_feed_status(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the current status of the Kubernetes official CVE feed."""
    feed = db.query(CVEFeed).filter(CVEFeed.name == K8S_FEED_NAME).first()
    if not feed:
        return {
            "registered": False,
            "feed_url": K8S_OFFICIAL_CVE_FEED_URL,
            "message": "Not yet registered. POST /cve/k8s/feed/sync to load it.",
        }
    return {
        "registered": True,
        "feed_id": str(feed.id),
        "feed_name": feed.name,
        "feed_url": feed.url,
        "enabled": feed.enabled,
        "entry_count": feed.entry_count,
        "last_fetched": feed.last_fetched.isoformat() if feed.last_fetched else None,
    }


# ── Per-cluster K8s CVE scanning ──────────────────────────────────────────────

@router.post("/k8s/clusters/{cluster_id}/scan")
async def scan_cluster(
    cluster_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Scan a registered Kubernetes cluster against all enabled CVE feeds.

    Discovers:
    - Kubernetes server version and node kubelet versions
    - Running add-ons (ingress-nginx, csi-driver-nfs, coredns, metrics-server, etc.)
      by inspecting container images in Deployments and DaemonSets

    Matches all discovered versions against CVE affected_components version ranges
    and returns a prioritised findings list (CRITICAL → HIGH → MEDIUM → LOW).
    """
    cluster = (
        db.query(ClusterRegistration)
        .filter(
            ClusterRegistration.id == cluster_id,
            ClusterRegistration.tenant_id == user.tenant_id,
        )
        .first()
    )
    if not cluster:
        raise HTTPException(404, "Cluster not found.")
    if not cluster.active:
        raise HTTPException(400, "Cluster is not active.")

    try:
        return await cve_service.scan_registered_cluster(cluster, user.tenant_id, db)
    except Exception as exc:
        raise HTTPException(502, f"Cluster scan failed: {exc}")


@router.post("/k8s/scan-all")
async def scan_all_clusters(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Scan every active registered cluster for this tenant."""
    results = await cve_service.scan_all_registered_clusters(user.tenant_id, db)
    return {"results": results, "clusters_scanned": len(results)}


@router.get("/k8s/clusters/{cluster_id}/scan/latest")
def get_latest_cluster_scan(
    cluster_id: UUID,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the most recent CVE scan result for a specific cluster."""
    cluster = (
        db.query(ClusterRegistration)
        .filter(
            ClusterRegistration.id == cluster_id,
            ClusterRegistration.tenant_id == user.tenant_id,
        )
        .first()
    )
    if not cluster:
        raise HTTPException(404, "Cluster not found.")

    result = cve_service.get_latest_cluster_scan(cluster_id, db)
    if not result:
        return {
            "message": f"No scans yet for cluster '{cluster.name}'. "
                       "POST /cve/k8s/clusters/{id}/scan to run the first scan."
        }
    return result


@router.get("/k8s/clusters/{cluster_id}/scan/history")
def get_cluster_scan_history(
    cluster_id: UUID,
    limit: int = 20,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """Return the scan history for a cluster, newest first."""
    cluster = (
        db.query(ClusterRegistration)
        .filter(
            ClusterRegistration.id == cluster_id,
            ClusterRegistration.tenant_id == user.tenant_id,
        )
        .first()
    )
    if not cluster:
        raise HTTPException(404, "Cluster not found.")

    return {
        "cluster_id": str(cluster_id),
        "cluster_name": cluster.name,
        "scans": cve_service.get_cluster_scan_history(cluster_id, db, limit=limit),
    }


@router.get("/k8s/clusters")
def list_clusters_with_scan_status(
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    List all registered clusters for this tenant with their latest CVE scan summary.
    Useful for the dashboard cluster picker.
    """
    clusters = (
        db.query(ClusterRegistration)
        .filter(ClusterRegistration.tenant_id == user.tenant_id)
        .order_by(ClusterRegistration.name)
        .all()
    )

    result = []
    for cluster in clusters:
        latest = (
            db.query(K8sCVEScanResult)
            .filter(K8sCVEScanResult.cluster_id == cluster.id)
            .order_by(K8sCVEScanResult.scanned_at.desc())
            .first()
        )
        result.append({
            "id": str(cluster.id),
            "name": cluster.name,
            "environment": cluster.environment,
            "active": cluster.active,
            "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
            "latest_scan": {
                "scanned_at": latest.scanned_at.isoformat(),
                "cluster_version": latest.cluster_version,
                "affected_count": latest.affected_count,
                "status": latest.status,
                "severity_breakdown": cve_service._severity_breakdown(latest.findings or []),
            } if latest else None,
        })
    return {"clusters": result}
