import os
import uuid
import secrets
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models, database, auth, audit
from .cve_service import cve_service as _cve_service
from .routers import cve, rbac

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Kaaval Control Plane", version="1.0.0")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", f"{FRONTEND_URL},http://localhost:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────

app.include_router(cve.router)
app.include_router(rbac.router)

# ── Default CVE feeds ──────────────────────────────────────────────────────────

DEFAULT_CVE_FEEDS = [
    {
        "name": "Kubernetes Official CVE Feed",
        "url": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
        "feed_type": "json_feed",
        "description": "Official Kubernetes security CVE feed — updated by the Kubernetes security team",
    },
    {
        "name": "NVD — Kubernetes CVEs",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&resultsPerPage=2000",
        "feed_type": "nvd",
        "description": "NIST NVD filtered for Kubernetes vulnerabilities (includes CVSS scores)",
    },
    {
        "name": "NVD — containerd CVEs",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=containerd&resultsPerPage=500",
        "feed_type": "nvd",
        "description": "NIST NVD filtered for containerd runtime vulnerabilities",
    },
]

# ── Admin bootstrap ────────────────────────────────────────────────────────────

def seed_admin_user(db: Session) -> dict:
    """Create the admin user on first run. Idempotent — safe to call on every startup."""
    user = db.query(models.User).filter(models.User.username == "admin").first()
    if user:
        return {"message": "Admin already exists"}
    default_password = os.getenv("KAAVAL_ADMIN_PASSWORD", secrets.token_urlsafe(12))
    tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    db.add(models.User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        username="admin",
        password_hash=auth.get_password_hash(default_password),
        role="admin",
    ))
    db.commit()
    # Only print the password if we generated it (not from env)
    if not os.getenv("KAAVAL_ADMIN_PASSWORD"):
        print(f"\n[Kaaval] Admin created — password: {default_password}\n")
        return {"message": "Admin created", "password": default_password}
    return {"message": "Admin created"}


# ── Scheduler ──────────────────────────────────────────────────────────────────

from apscheduler.schedulers.asyncio import AsyncIOScheduler

_scheduler = AsyncIOScheduler()


async def _scheduled_cve_refresh():
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Scheduled CVE feed refresh started")
    db = database.SessionLocal()
    try:
        results = await _cve_service.refresh_all_feeds(db)
        total = sum(r.get("entries_loaded", 0) for r in results if "entries_loaded" in r)
        logger.info(f"CVE refresh complete: {total} entries across {len(results)} feeds")
    except Exception as e:
        logger.error(f"CVE refresh failed: {e}")
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    models.Base.metadata.create_all(bind=database.engine)

    db = database.SessionLocal()
    try:
        # Seed default tenant
        default_tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        tenant = db.query(models.Tenant).filter(models.Tenant.id == default_tenant_id).first()
        if not tenant:
            db.add(models.Tenant(id=default_tenant_id, name="Default"))
            db.commit()

        # Seed default CVE feeds
        for feed_data in DEFAULT_CVE_FEEDS:
            if not db.query(models.CVEFeed).filter(models.CVEFeed.name == feed_data["name"]).first():
                db.add(models.CVEFeed(**feed_data))
        db.commit()

        # Seed admin user (idempotent — safe on every restart)
        seed_admin_user(db)
    finally:
        db.close()

    _scheduler.add_job(
        _scheduled_cve_refresh,
        trigger="interval",
        hours=24,
        id="refresh_cve_feeds",
        replace_existing=True,
    )

    _scheduler.start()


@app.on_event("shutdown")
async def shutdown_event():
    _scheduler.shutdown(wait=False)


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/")
def health_check():
    return {"status": "ok", "service": "Kaaval Control Plane", "version": "1.0.0"}


# ── Auth ───────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshRequest(BaseModel):
    refresh_token: str


class MeResponse(BaseModel):
    username: str
    role: str
    tenant_id: str


@app.post("/auth/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        audit.audit(
            db, form_data.username, "auth.login_failure",
            resource_type="auth", outcome="failure",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    refresh_token = auth.create_refresh_token(data={"sub": user.username})
    audit.audit(
        db, user, "auth.login_success",
        resource_type="auth", outcome="success",
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/auth/refresh", response_model=Token)
async def refresh(body: RefreshRequest, db: Session = Depends(database.get_db)):
    username = auth.decode_refresh_token(body.refresh_token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "access_token": auth.create_access_token(data={"sub": user.username}),
        "refresh_token": auth.create_refresh_token(data={"sub": user.username}),
        "token_type": "bearer",
    }


@app.post("/auth/seed")
def seed_admin(db: Session = Depends(database.get_db)):
    """Manually (re-)run admin bootstrap. Also called automatically on startup."""
    return seed_admin_user(db)


@app.get("/auth/me", response_model=MeResponse)
def get_me(current_user: models.User = Depends(auth.get_current_active_user)):
    return {
        "username": current_user.username,
        "role": current_user.role,
        "tenant_id": str(current_user.tenant_id),
    }
