"""Regression tests for persisted RBAC scan diffs and the HTTP endpoint."""

from types import SimpleNamespace
from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from app.auth import get_current_active_user
from app.database import get_db
from app.models import RBACScanResult
from app.rbac_service import diff_latest_scans
from app.routers.rbac import router


def _finding(rule_type, role_name, binding_name, **extra):
    return {
        "rule_type": rule_type,
        "role": {"kind": "ClusterRole", "name": role_name},
        "binding": {
            "kind": "ClusterRoleBinding",
            "name": binding_name,
            "namespace": None,
        },
        **extra,
    }


class _FakeQuery:
    def __init__(self, scans):
        self.scans = scans
        self.limit_value = None

    def order_by(self, *_clauses):
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def all(self):
        return self.scans[: self.limit_value]


class _FakeSession:
    def __init__(self, scans):
        self.scans = scans

    def query(self, model):
        assert model is RBACScanResult
        return _FakeQuery(self.scans)


def _scan(findings):
    return SimpleNamespace(findings=findings)


def _db(scans):
    return cast(Session, _FakeSession(scans))


def test_diff_latest_scans_reports_added_resolved_and_unchanged_findings():
    unchanged_latest = _finding(
        "wildcard_permissions",
        "shared-role",
        "shared-binding",
        severity="CRITICAL",
    )
    added = _finding("broad_secrets_access", "new-role", "new-binding")
    unchanged_previous = _finding(
        "wildcard_permissions",
        "shared-role",
        "shared-binding",
        severity="CRITICAL",
    )
    resolved = _finding("exec_attach_grant", "old-role", "old-binding")
    db = _db(
        [
            _scan([unchanged_latest, added]),
            _scan([unchanged_previous, resolved]),
        ]
    )

    result = diff_latest_scans(db)

    assert result == {
        "added": [added],
        "resolved": [resolved],
        "severity_changed": [],
        "unchanged_count": 1,
    }


@pytest.mark.parametrize(
    ("previous_severity", "latest_severity"),
    [("HIGH", "CRITICAL"), ("CRITICAL", "HIGH")],
)
def test_diff_latest_scans_reports_severity_changes(
    previous_severity, latest_severity
):
    previous = _finding(
        "wildcard_permissions",
        "shared-role",
        "shared-binding",
        severity=previous_severity,
    )
    latest = _finding(
        "wildcard_permissions",
        "shared-role",
        "shared-binding",
        severity=latest_severity,
    )

    result = diff_latest_scans(_db([_scan([latest]), _scan([previous])]))

    assert result == {
        "added": [],
        "resolved": [],
        "severity_changed": [
            {
                "finding": latest,
                "previous_severity": previous_severity,
            }
        ],
        "unchanged_count": 0,
    }


@pytest.mark.parametrize("scans", [[], [_scan([])]])
def test_diff_latest_scans_handles_fewer_than_two_scans(scans):
    assert diff_latest_scans(_db(scans)) == {
        "added": [],
        "resolved": [],
        "severity_changed": [],
        "unchanged_count": 0,
    }


def test_diff_latest_scans_treats_missing_findings_as_empty():
    added = _finding("token_creation", "token-minter", "token-binding")

    result = diff_latest_scans(_db([_scan([added]), _scan(None)]))

    assert result == {
        "added": [added],
        "resolved": [],
        "severity_changed": [],
        "unchanged_count": 0,
    }


def test_diff_latest_scans_collapses_duplicate_finding_keys():
    older_duplicate = _finding(
        "wildcard_permissions",
        "wide-open",
        "wide-open-binding",
        severity="HIGH",
    )
    newer_duplicate = _finding(
        "wildcard_permissions",
        "wide-open",
        "wide-open-binding",
        severity="CRITICAL",
    )

    result = diff_latest_scans(
        _db(
            [
                _scan([older_duplicate, newer_duplicate]),
                _scan([]),
            ]
        )
    )

    assert result["added"] == [newer_duplicate]
    assert result["resolved"] == []
    assert result["severity_changed"] == []
    assert result["unchanged_count"] == 0


@pytest.fixture
def api_app():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_active_user] = lambda: SimpleNamespace(
        tenant_id="test-tenant"
    )
    yield app
    app.dependency_overrides.clear()


def test_get_rbac_scan_diff_api_returns_service_contract(api_app):
    added = _finding("csr_approval", "approver", "approver-binding")
    resolved = _finding("pv_creation", "pv-creator", "pv-binding")
    unchanged = _finding("workload_creation", "deployer", "deployer-binding")
    db = _db(
        [
            _scan([added, unchanged]),
            _scan([resolved, unchanged]),
        ]
    )
    api_app.dependency_overrides[get_db] = lambda: db

    with TestClient(api_app) as client:
        response = client.get("/rbac/scan/diff")

    assert response.status_code == 200
    assert response.json() == {
        "added": [added],
        "resolved": [resolved],
        "severity_changed": [],
        "unchanged_count": 1,
    }


def test_get_rbac_scan_diff_api_handles_no_scan_history(api_app):
    api_app.dependency_overrides[get_db] = lambda: _db([])

    with TestClient(api_app) as client:
        response = client.get("/rbac/scan/diff")

    assert response.status_code == 200
    assert response.json() == {
        "added": [],
        "resolved": [],
        "severity_changed": [],
        "unchanged_count": 0,
    }
