"""
Smoke test for the v1 detector flow: admin bootstrap -> login -> self-scan.

Requires a reachable Postgres instance (DATABASE_URL, defaults to the same
local docker-compose database as the app itself). Run from control-plane/:

    KAAVAL_ADMIN_PASSWORD=test-admin-password pytest tests/test_smoke.py
"""

import os

os.environ.setdefault("KAAVAL_ADMIN_PASSWORD", "test-admin-password")

from fastapi.testclient import TestClient

from app.main import app

ADMIN_PASSWORD = os.environ["KAAVAL_ADMIN_PASSWORD"]


def test_login_and_self_scan():
    with TestClient(app) as client:
        # Admin user is auto-seeded on startup (see app.main.seed_admin_user)
        resp = client.post(
            "/auth/token",
            data={"username": "admin", "password": ADMIN_PASSWORD},
        )
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.get("/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"

        resp = client.post("/cve/scan", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "severity_breakdown" in body
        assert "findings" in body

        resp = client.get("/cve/summary", headers=headers)
        assert resp.status_code == 200
        assert "total_cves" in resp.json()

        # Risk context: defaults on first access, then updatable.
        # Drop any persisted context first — a previous run's PUT below would
        # otherwise leak into this assertion on a reused local database.
        from app import database as _database, models as _models
        _db = _database.SessionLocal()
        try:
            _db.query(_models.ScanContext).delete()
            _db.commit()
        finally:
            _db.close()

        resp = client.get("/cve/context", headers=headers)
        assert resp.status_code == 200, resp.text
        context = resp.json()
        assert context["environment"] == "production"

        resp = client.put(
            "/cve/context", headers=headers,
            json={"environment": "dev", "data_classification": "pii", "compliance_scope": ["PCI-DSS"]},
        )
        assert resp.status_code == 200, resp.text
        updated = resp.json()
        assert updated["environment"] == "dev"
        assert updated["data_classification"] == "pii"
        assert updated["compliance_scope"] == ["PCI-DSS"]

        resp = client.put("/cve/context", headers=headers, json={"environment": "not-a-real-env"})
        assert resp.status_code == 400
