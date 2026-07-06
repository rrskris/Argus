from sqlalchemy import Column, String, DateTime, Text, JSON, ForeignKey, Integer, Boolean, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
import datetime
from .database import Base


# ── Core ───────────────────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer")  # admin | editor | viewer
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    prefix = Column(String, nullable=False)
    key_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


# ── Agent / Endpoint ───────────────────────────────────────────────────────────

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    os_info = Column(String, nullable=True)
    # packages: [{name, version, arch}] — populated by agent package scan
    packages = Column(JSON, nullable=True)
    status = Column(String, nullable=False, default="OFFLINE")
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    enrollment_key = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


# ── Cloud / CSPM ───────────────────────────────────────────────────────────────

class CloudAccount(Base):
    __tablename__ = "cloud_accounts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    account_name = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    role_arn = Column(String, nullable=False)
    external_id = Column(String, nullable=True)
    provider = Column(String, default="AWS")  # AWS | DigitalOcean | GCP | Azure
    status = Column(String, default="pending")  # pending | active | error
    last_scanned = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    account_id = Column(String, nullable=True)
    status = Column(String, nullable=False)  # PENDING | IN_PROGRESS | COMPLETED | FAILED
    region = Column(String, nullable=True)
    requested_at = Column(DateTime, default=datetime.datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True)
    asset_type = Column(String, primary_key=True)  # EC2 | IAM_USER | S3_BUCKET | EKS_CLUSTER | VPC
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"))
    region = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    vpc_id = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String, primary_key=True)  # CVE-XXX or GHSA-XXX
    source = Column(String, nullable=False)  # NVD | OSV
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    affected_packages = Column(JSON, nullable=True)
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=False)
    asset_id = Column(String, nullable=False)
    asset_type = Column(String, nullable=False)
    scan_id = Column(UUID(as_uuid=True), nullable=False)
    status = Column(String, default="Active")  # Active | Fixed | Mitigated
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)


# ── Compliance ─────────────────────────────────────────────────────────────────

class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    id = Column(String, primary_key=True)  # e.g. "cis-aws-1.5"
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    version = Column(String, nullable=False)
    is_premium = Column(Boolean, default=False)
    price_tier = Column(String, default="free")  # free | standard | enterprise


class TenantFramework(Base):
    __tablename__ = "tenant_frameworks"
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), primary_key=True)
    framework_id = Column(String, ForeignKey("compliance_frameworks.id"), primary_key=True)
    status = Column(String, default="active")  # active | disabled
    enabled_at = Column(DateTime, default=datetime.datetime.utcnow)


# ── CVE Feeds ──────────────────────────────────────────────────────────────────

class CVEFeed(Base):
    __tablename__ = "cve_feeds"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=False)
    feed_type = Column(String, default="auto")  # auto | json_feed | osv | nvd
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    last_fetched = Column(DateTime, nullable=True)
    entry_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    entries = relationship("CVEEntry", back_populates="feed", cascade="all, delete-orphan", passive_deletes=True)


class CVEEntry(Base):
    __tablename__ = "cve_entries"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id = Column(UUID(as_uuid=True), ForeignKey("cve_feeds.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String, default="UNKNOWN")  # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    cvss_score = Column(Float, nullable=True)
    affected_components = Column(JSON, nullable=True)
    fixed_in = Column(JSON, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    references = Column(JSON, nullable=True)
    feed = relationship("CVEFeed", back_populates="entries")


class CVEScanResult(Base):
    __tablename__ = "cve_scan_results"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    cluster_version = Column(String, nullable=True)
    node_versions = Column(JSON, nullable=True)
    addons = Column(JSON, nullable=True)
    total_cves_checked = Column(Integer, default=0)
    affected_count = Column(Integer, default=0)
    findings = Column(JSON, nullable=True)
    status = Column(String, default="completed")


# ── Integration Hub ────────────────────────────────────────────────────────────

class IntegrationConfig(Base):
    """A configured external tool integration for a tenant."""
    __tablename__ = "integration_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    plugin_id = Column(String, nullable=False)      # e.g. "wazuh" | "syslog" | "aws"
    name = Column(String, nullable=False)            # user-provided label
    enabled = Column(Boolean, default=True)
    # Encrypted credentials + connector config (host, port, api_key, etc.)
    config = Column(JSON, nullable=False, default=dict)
    # Connector type: pull | push | agent_module
    connector_type = Column(String, nullable=False, default="pull")
    last_synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    findings = relationship("IntegrationFinding", back_populates="integration", cascade="all, delete-orphan")


class IntegrationFinding(Base):
    """Canonical finding ingested from any external integration."""
    __tablename__ = "integration_findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integration_configs.id", ondelete="CASCADE"), nullable=False)
    source_tool = Column(String, nullable=False)     # e.g. "wazuh" | "crowdstrike"
    finding_type = Column(String, nullable=False)    # vuln | alert | policy_violation | log_event
    severity = Column(String, nullable=False, default="UNKNOWN")  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    raw_payload = Column(JSON, nullable=True)
    asset_id = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    detected_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    ingested_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="open")          # open | acknowledged | resolved
    integration = relationship("IntegrationConfig", back_populates="findings")


# ── Dashboard / Widget Canvas ──────────────────────────────────────────────────

class DashboardLayout(Base):
    """A named widget canvas belonging to a user."""
    __tablename__ = "dashboard_layouts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    widgets = relationship("WidgetInstance", back_populates="dashboard", cascade="all, delete-orphan")


class WidgetInstance(Base):
    """A single widget tile placed on a dashboard."""
    __tablename__ = "widget_instances"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dashboard_id = Column(UUID(as_uuid=True), ForeignKey("dashboard_layouts.id", ondelete="CASCADE"), nullable=False)
    widget_type = Column(String, nullable=False)     # stat_card | cve_heatmap | compliance_gauge | ...
    title = Column(String, nullable=True)
    grid_x = Column(Integer, nullable=False, default=0)
    grid_y = Column(Integer, nullable=False, default=0)
    grid_w = Column(Integer, nullable=False, default=2)
    grid_h = Column(Integer, nullable=False, default=2)
    config = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    dashboard = relationship("DashboardLayout", back_populates="widgets")


# ── EE Features ────────────────────────────────────────────────────────────────

class AttestationKey(Base):
    __tablename__ = "attestation_keys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    name = Column(String, nullable=False)
    algorithm = Column(String, nullable=False, default="ES256")
    public_key_pem = Column(Text, nullable=False)
    fingerprint = Column(String, nullable=False, index=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    rotated_at = Column(DateTime, nullable=True)


class AttestationRecord(Base):
    __tablename__ = "attestation_records"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    key_id = Column(UUID(as_uuid=True), ForeignKey("attestation_keys.id"), nullable=False)
    subject = Column(String, nullable=False)
    subject_type = Column(String, nullable=False, default="pod")
    payload_hash = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
    signed_at = Column(DateTime, default=datetime.datetime.utcnow)
    metadata_ = Column("metadata", JSON, nullable=True)


class ClusterRegistration(Base):
    __tablename__ = "cluster_registrations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    name = Column(String, nullable=False)
    api_server_url = Column(String, nullable=False)
    bearer_token = Column(Text, nullable=False)
    ca_cert_pem = Column(Text, nullable=True)
    environment = Column(String, default="production")
    active = Column(Boolean, default=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class OIDCConfig(Base):
    __tablename__ = "oidc_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, unique=True)
    provider_name = Column(String, nullable=False)
    issuer_url = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    client_secret = Column(Text, nullable=False)
    redirect_uri = Column(String, nullable=False)
    scopes = Column(String, default="openid email profile")
    attribute_mapping = Column(JSON, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class K8sCVEScanResult(Base):
    """Per-cluster Kubernetes CVE scan result — one row per scan run."""
    __tablename__ = "k8s_cve_scan_results"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(UUID(as_uuid=True), ForeignKey("cluster_registrations.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    cluster_version = Column(String, nullable=True)          # e.g. "1.29.3"
    node_versions = Column(JSON, nullable=True)              # ["1.29.2", "1.29.3"]
    addons = Column(JSON, nullable=True)                     # [{"name", "version", "namespace", "workload"}]
    total_cves_checked = Column(Integer, default=0)
    affected_count = Column(Integer, default=0)
    findings = Column(JSON, nullable=True)                   # list of finding dicts
    status = Column(String, default="completed")             # completed | failed
    error = Column(Text, nullable=True)
    cluster = relationship("ClusterRegistration")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    actor = Column(String, nullable=False)
    actor_ip = Column(String, nullable=True)
    action = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    outcome = Column(String, nullable=False, default="success")
    detail = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)


class SIEMConfig(Base):
    __tablename__ = "siem_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    name = Column(String, nullable=False)
    siem_type = Column(String, nullable=False, default="webhook")  # splunk_hec | elastic | webhook
    endpoint_url = Column(String, nullable=False)
    api_key = Column(Text, nullable=True)
    filters = Column(JSON, nullable=True)
    enabled = Column(Boolean, default=True)
    last_forwarded_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
