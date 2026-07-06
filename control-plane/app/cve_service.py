"""
CVE Feed Service — fetches, parses, and evaluates CVE data against live cluster state.

Supported feed formats (auto-detected):
  - JSON Feed 1.0  : kubernetes.io official CVE feed (with embedded OSV extraction)
  - OSV            : Open Source Vulnerability format (osv.dev, GitHub Advisory)
  - NVD JSON 2.0   : NIST National Vulnerability Database

K8s cluster scanning:
  - Scans any registered ClusterRegistration via bearer token + API server URL
  - Detects Kubernetes core version AND running add-ons (ingress-nginx, csi-*, coredns)
  - Matches both against affected_components version ranges from CVE entries
"""

import json
import re
import logging
import ssl
import tempfile
import os
from datetime import datetime
from typing import Optional
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from .models import CVEFeed, CVEEntry, CVEScanResult, K8sCVEScanResult, ClusterRegistration
from .addon_detection import ADDON_IMAGE_PATTERNS, image_version as _image_version

logger = logging.getLogger(__name__)

# Official Kubernetes CVE feed URL
K8S_OFFICIAL_CVE_FEED_URL = "https://k8s.io/docs/reference/issues-security/official-cve-feed/index.json"
K8S_FEED_NAME = "Kubernetes Official CVE Feed"

# ── Version helpers ────────────────────────────────────────────────────────────

def _parse_semver(v: str) -> tuple:
    """Parse a semver string like '1.28.4' or 'v1.28.4' into (major, minor, patch)."""
    v = v.lstrip("v").strip()
    parts = re.split(r"[.\-+]", v)
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _version_in_range(version: str, introduced: str, fixed: Optional[str]) -> bool:
    """Return True if version >= introduced and (no fixed, or version < fixed)."""
    v = _parse_semver(version)
    intro = _parse_semver(introduced) if introduced and introduced != "0" else (0, 0, 0)
    if v < intro:
        return False
    if fixed:
        fix = _parse_semver(fixed)
        if v >= fix:
            return False
    return True


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


# ── Embedded OSV extractor (used by K8s JSON Feed items) ──────────────────────

def _extract_osv_from_content(content_text: str) -> Optional[dict]:
    """
    The K8s official CVE feed embeds a full OSV JSON block in content_text:

        ```json osv
        { "id": "CVE-...", "affected": [...], "severity": [...] }
        ```

    This function extracts and parses that block, returning the OSV dict or None.
    """
    match = re.search(r"```json\s+osv\s*(.*?)```", content_text, re.DOTALL | re.IGNORECASE)
    if not match:
        return None
    try:
        return json.loads(match.group(1).strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_osv_affected(osv: dict) -> tuple[list, list]:
    """
    Extract (affected_components, fixed_versions) from an OSV dict.
    Returns the same structure used by CVEEntry.affected_components.
    """
    affected_components = []
    fixed_versions = []

    for affected in osv.get("affected", []):
        pkg = affected.get("package", {})
        ranges = []
        # Each SEMVER range can have multiple introduced/fixed pairs
        # The K8s feed sometimes chains them: intro=0,fixed=X, intro=0,fixed=Y
        # meaning there are separate vulnerable branches
        for r in affected.get("ranges", []):
            events = r.get("events", [])
            introduced = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                    fixed_versions.append(fixed)
                    ranges.append({
                        "type": r.get("type", "SEMVER"),
                        "introduced": introduced or "0",
                        "fixed": fixed,
                    })
                    # Don't reset introduced — next event may be another introduced
        # If we got events but no fixed (ongoing), still record the range
        if not ranges and introduced:
            ranges.append({
                "type": "SEMVER",
                "introduced": introduced,
                "fixed": None,
            })

        affected_components.append({
            "component": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "ranges": ranges,
            "versions": affected.get("versions", []),
        })

    return affected_components, fixed_versions


# ── Format parsers ─────────────────────────────────────────────────────────────

def _parse_json_feed(data: dict, feed_id: UUID) -> list:
    """
    Parse JSON Feed 1.0 format — used by kubernetes.io official CVE feed.

    Key difference from a generic JSON Feed: each K8s item embeds a full OSV
    JSON block inside content_text. We extract that for structured version data.
    The item's `id` field IS the CVE ID (e.g. "CVE-2025-1234"), and `summary`
    is the human-readable title.
    """
    entries = []
    for item in data.get("items", []):
        # The K8s feed uses `id` directly as the CVE ID
        raw_id = item.get("id", "")
        cve_match = re.search(r"CVE-\d{4}-\d+", raw_id)
        cve_id = cve_match.group(0) if cve_match else raw_id

        title = item.get("summary", item.get("title", cve_id))
        content_text = item.get("content_text", item.get("content_html", ""))
        content_clean = _strip_html(content_text)

        # ── Extract embedded OSV for structured version ranges ─────────────
        osv = _extract_osv_from_content(content_text)
        affected_components, fixed_versions = [], []
        if osv:
            affected_components, fixed_versions = _parse_osv_affected(osv)

        # ── CVSS / severity ────────────────────────────────────────────────
        cvss_score = None
        severity = "UNKNOWN"

        # Try to get CVSS from embedded OSV severity block first (most accurate)
        if osv:
            for sev_entry in osv.get("severity", []):
                score_str = sev_entry.get("score", "")
                # CVSS:3.1/AV:N/AC:L/... — base score is last component
                base_match = re.search(r"(\d+\.\d+)$", score_str)
                if base_match:
                    try:
                        cvss_score = float(base_match.group(1))
                    except ValueError:
                        pass

        # Fall back to parsing content text
        if cvss_score is None:
            cvss_match = re.search(
                r"CVSS[^:]*?(?:Rating)?[:\s]+(?:\[)?(?:[\d.]{3,4})\s*\((\w+)\)",
                content_clean, re.IGNORECASE
            )
            if cvss_match:
                sev_word = cvss_match.group(1).upper()
                severity = sev_word if sev_word in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"

            numeric_match = re.search(r"(\d+\.\d+)\s*\((?:Critical|High|Medium|Low)\)", content_clean, re.IGNORECASE)
            if numeric_match:
                try:
                    cvss_score = float(numeric_match.group(1))
                except ValueError:
                    pass

        if cvss_score is not None and severity == "UNKNOWN":
            severity = _cvss_to_severity(cvss_score)

        refs = []
        if item.get("url"):
            refs.append({"url": item["url"], "type": "ADVISORY"})
        if item.get("external_url"):
            refs.append({"url": item["external_url"], "type": "ADVISORY"})

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": title[:500],
            "description": content_clean[:2000],
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_components": affected_components,
            "fixed_in": list(set(fixed_versions)) or None,
            "published_date": _parse_iso(item.get("date_published")),
            "modified_date": _parse_iso(item.get("date_modified")),
            "references": refs,
        })
    return entries


def _parse_osv(data: dict, feed_id: UUID) -> list:
    """Parse OSV (Open Source Vulnerability) format — osv.dev, GitHub Advisory DB."""
    raw_vulns = data.get("vulns", [])
    if not raw_vulns:
        raw_vulns = [data] if "id" in data else []

    entries = []
    for vuln in raw_vulns:
        cve_id = vuln.get("id", "UNKNOWN")
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        cvss_score = None
        severity = "UNKNOWN"
        db_specific = vuln.get("database_specific", {})
        if "cvss" in db_specific:
            cvss_data = db_specific["cvss"]
            cvss_score = cvss_data.get("score")
            severity = cvss_data.get("severity", "UNKNOWN").upper()
        elif "severity" in db_specific:
            severity = str(db_specific["severity"]).upper()

        for sev_entry in vuln.get("severity", []):
            score_str = sev_entry.get("score", "")
            base_match = re.search(r"(\d+\.\d+)$", score_str)
            if base_match and cvss_score is None:
                try:
                    cvss_score = float(base_match.group(1))
                except ValueError:
                    pass

        if severity == "UNKNOWN" and cvss_score is not None:
            severity = _cvss_to_severity(float(cvss_score))

        affected_components, fixed_versions = _parse_osv_affected(vuln)
        refs = [{"url": r.get("url", ""), "type": r.get("type", "WEB")} for r in vuln.get("references", [])]

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": vuln.get("summary", cve_id)[:500],
            "description": vuln.get("details", "")[:2000],
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "affected_components": affected_components,
            "fixed_in": list(set(fixed_versions)) or None,
            "published_date": _parse_iso(vuln.get("published")),
            "modified_date": _parse_iso(vuln.get("modified")),
            "references": refs,
        })
    return entries


def _parse_nvd(data: dict, feed_id: UUID) -> list:
    """Parse NVD JSON 2.0 format — nvd.nist.gov."""
    entries = []
    for wrapper in data.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        cvss_score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                break

        affected_components = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if not cpe.get("vulnerable"):
                        continue
                    parts = cpe.get("criteria", "").split(":")
                    component = parts[4] if len(parts) > 4 else "unknown"
                    ver_start = cpe.get("versionStartIncluding", "0")
                    ver_end = cpe.get("versionEndExcluding")
                    ranges = []
                    if ver_start or ver_end:
                        ranges.append({
                            "type": "SEMVER",
                            "introduced": ver_start or "0",
                            "fixed": ver_end,
                        })
                    affected_components.append({
                        "component": component,
                        "ecosystem": "NVD",
                        "ranges": ranges,
                        "versions": [],
                    })

        refs = [{"url": r.get("url", ""), "type": r.get("type", "WEB")} for r in cve.get("references", [])]

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": f"{cve_id}: {desc[:100]}",
            "description": desc[:2000],
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "affected_components": affected_components,
            "fixed_in": None,
            "published_date": _parse_iso(cve.get("published")),
            "modified_date": _parse_iso(cve.get("lastModified")),
            "references": refs,
        })
    return entries


# ── Feed detection ─────────────────────────────────────────────────────────────

def _detect_and_parse(data: dict, feed_id: UUID) -> list:
    """Auto-detect feed format and dispatch to the right parser."""
    if "vulnerabilities" in data:
        return _parse_nvd(data, feed_id)
    if "vulns" in data or ("id" in data and "affected" in data and "references" in data):
        return _parse_osv(data, feed_id)
    if "items" in data:
        return _parse_json_feed(data, feed_id)
    logger.warning(f"Unrecognised feed format for feed_id={feed_id}; keys={list(data.keys())[:10]}")
    return []


# ── Remote K8s cluster client ──────────────────────────────────────────────────


class RemoteK8sClient:
    """
    Thin async HTTP client for a registered Kubernetes cluster.
    Uses the stored bearer token and API server URL from ClusterRegistration.
    TLS verification uses the stored CA cert when available, otherwise skips.
    """

    def __init__(self, cluster: ClusterRegistration):
        self.cluster_id = str(cluster.id)
        self.cluster_name = cluster.name
        self.base_url = cluster.api_server_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {cluster.bearer_token}",
            "Accept": "application/json",
        }
        self._ca_cert_pem = cluster.ca_cert_pem  # may be None

    def _build_client(self) -> httpx.AsyncClient:
        if self._ca_cert_pem:
            # Write CA cert to a temp file for httpx
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w")
            tmp.write(self._ca_cert_pem)
            tmp.close()
            return httpx.AsyncClient(verify=tmp.name, timeout=20.0)
        else:
            return httpx.AsyncClient(verify=False, timeout=20.0)

    async def get(self, path: str) -> dict:
        async with self._build_client() as client:
            r = await client.get(f"{self.base_url}{path}", headers=self.headers)
            r.raise_for_status()
            return r.json()

    async def get_server_version(self) -> str:
        """Return the Kubernetes server version string, e.g. '1.29.3'."""
        data = await self.get("/version")
        git_version = data.get("gitVersion", "").lstrip("v").split("-")[0]
        if git_version:
            return git_version
        major = re.sub(r"\D", "", data.get("major", "0"))
        minor = re.sub(r"\D", "", data.get("minor", "0"))
        return f"{major}.{minor}"

    async def get_node_versions(self) -> list[str]:
        """Return a deduplicated list of kubelet versions running on nodes."""
        data = await self.get("/api/v1/nodes")
        versions = set()
        for item in data.get("items", []):
            v = (
                item.get("status", {})
                    .get("nodeInfo", {})
                    .get("kubeletVersion", "")
                    .lstrip("v")
                    .split("-")[0]
            )
            if v:
                versions.add(v)
        return sorted(versions)

    async def detect_addons(self) -> list[dict]:
        """
        Scan all Deployments and DaemonSets cluster-wide to detect running
        add-ons and their versions by matching container image names.

        Returns a list of dicts: {name, version, namespace, workload, image}
        """
        addons: list[dict] = []
        seen: set[tuple] = set()  # (addon_name, version) dedup

        for resource in ("/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets"):
            try:
                data = await self.get(resource)
            except Exception as exc:
                logger.warning(f"[{self.cluster_name}] Failed to list {resource}: {exc}")
                continue

            for item in data.get("items", []):
                ns = item.get("metadata", {}).get("namespace", "")
                workload_name = item.get("metadata", {}).get("name", "")
                spec = item.get("spec", {}).get("template", {}).get("spec", {})
                containers = spec.get("containers", []) + spec.get("initContainers", [])

                for container in containers:
                    image = container.get("image", "")
                    for addon_name, pattern in ADDON_IMAGE_PATTERNS.items():
                        if pattern.search(image):
                            version = _image_version(image) or "unknown"
                            key = (addon_name, version)
                            if key not in seen:
                                seen.add(key)
                                addons.append({
                                    "name": addon_name,
                                    "version": version,
                                    "namespace": ns,
                                    "workload": workload_name,
                                    "image": image,
                                })
        return addons


# ── CVE matching ───────────────────────────────────────────────────────────────

def _match_cves(
    entries: list,
    server_version: str,
    node_versions: list[str],
    addons: list[dict],
) -> list[dict]:
    """
    Compare CVE entries against the collected cluster inventory.

    Builds a lookup: component_name → set of versions present in this cluster.
    For each CVE entry, checks whether any present version falls within an
    affected version range.  Returns sorted findings list.
    """
    # Build component → versions map
    versions_map: dict[str, set[str]] = {"kubernetes": set()}
    if server_version and server_version != "unknown":
        versions_map["kubernetes"].add(server_version)
    for v in node_versions:
        versions_map["kubernetes"].add(v)

    for addon in addons:
        name = addon["name"].lower()
        if name not in versions_map:
            versions_map[name] = set()
        if addon["version"] != "unknown":
            versions_map[name].add(addon["version"])

    findings = []
    for entry in entries:
        affected_matches = []
        for comp in (entry.affected_components or []):
            comp_name = comp.get("component", "").lower()
            if not comp_name:
                continue

            # Find which of our known components this CVE is about
            candidate_versions: set[str] = set()
            for known_name, known_versions in versions_map.items():
                if known_name == comp_name or comp_name in known_name or known_name in comp_name:
                    candidate_versions |= known_versions

            for ver in candidate_versions:
                # Check explicit version list first
                if any(
                    v.lstrip("v").split("-")[0] == ver
                    for v in comp.get("versions", [])
                ):
                    affected_matches.append({
                        "component": comp_name,
                        "version": ver,
                        "fixed": comp.get("fixed_in"),
                    })
                    continue
                # Check semver ranges
                for r in comp.get("ranges", []):
                    if _version_in_range(ver, r.get("introduced", "0"), r.get("fixed")):
                        affected_matches.append({
                            "component": comp_name,
                            "version": ver,
                            "fixed": r.get("fixed"),
                        })
                        break

        if affected_matches:
            findings.append({
                "cve_id": entry.cve_id,
                "title": entry.title,
                "severity": entry.severity,
                "cvss_score": entry.cvss_score,
                "affected": affected_matches,
                "fixed_in": entry.fixed_in,
                "description": (entry.description or "")[:500],
                "references": (entry.references or [])[:3],
                "published_date": entry.published_date.isoformat() if entry.published_date else None,
            })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda x: (sev_order.get(x["severity"], 4), -(x["cvss_score"] or 0)))
    return findings


def _severity_breakdown(findings: list) -> dict:
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        breakdown[sev] = breakdown.get(sev, 0) + 1
    return breakdown


# ── Main service ───────────────────────────────────────────────────────────────

class CVEFeedService:

    # ── Feed management ────────────────────────────────────────────────────────

    async def fetch_and_parse(self, feed: CVEFeed) -> list:
        """Fetch a feed URL and return parsed entry dicts."""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(feed.url, headers={"Accept": "application/json, */*"})
            resp.raise_for_status()
            data = resp.json()
        return _detect_and_parse(data, feed.id)

    async def ensure_k8s_feed(self, db: Session) -> CVEFeed:
        """
        Ensure the official Kubernetes CVE feed is registered in the DB.
        Creates it if missing.  Does NOT auto-refresh (call refresh_feed for that).
        """
        feed = db.query(CVEFeed).filter(CVEFeed.name == K8S_FEED_NAME).first()
        if not feed:
            feed = CVEFeed(
                name=K8S_FEED_NAME,
                url=K8S_OFFICIAL_CVE_FEED_URL,
                feed_type="json_feed",
                description=(
                    "Auto-refreshing official CVE feed from kubernetes.io — "
                    "includes all Kubernetes core and add-on CVEs with embedded OSV data."
                ),
            )
            db.add(feed)
            db.commit()
            db.refresh(feed)
            logger.info(f"Registered K8s official CVE feed (id={feed.id})")
        return feed

    async def refresh_feed(self, feed_id: UUID, db: Session) -> dict:
        feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
        if not feed:
            raise ValueError(f"Feed {feed_id} not found")

        try:
            entries = await self.fetch_and_parse(feed)
        except Exception as e:
            logger.error(f"Failed to fetch feed '{feed.name}': {e}")
            raise

        db.query(CVEEntry).filter(CVEEntry.feed_id == feed_id).delete(synchronize_session=False)
        for entry_data in entries:
            db.add(CVEEntry(**entry_data))

        feed.last_fetched = datetime.utcnow()
        feed.entry_count = len(entries)
        db.commit()

        logger.info(f"Feed '{feed.name}' refreshed: {len(entries)} entries loaded.")
        return {"feed": feed.name, "entries_loaded": len(entries)}

    async def refresh_all_feeds(self, db: Session) -> list:
        feeds = db.query(CVEFeed).filter(CVEFeed.enabled == True).all()
        results = []
        for feed in feeds:
            try:
                result = await self.refresh_feed(feed.id, db)
                results.append(result)
            except Exception as e:
                logger.error(f"Feed '{feed.name}' refresh failed: {e}")
                results.append({"feed": feed.name, "error": str(e)})
        return results

    # ── In-cluster scan (legacy — uses in-cluster kubeconfig) ─────────────────

    def _collect_cluster_inventory(self) -> tuple:
        """Returns (server_version, node_versions_set, addons_list) for the in-cluster scan."""
        server_version = "unknown"
        all_versions: set = set()
        addons: list = []
        try:
            from .k8s_client import K8sClient
            k8s = K8sClient()
            info = k8s.version_api.get_code()
            major = re.sub(r"\D", "", info.major or "0")
            minor = re.sub(r"\D", "", info.minor or "0")
            git_ver = (info.git_version or "").lstrip("v").split("-")[0]
            server_version = git_ver if git_ver else f"{major}.{minor}"
            all_versions.add(server_version)
            nodes = k8s.get_nodes()
            if isinstance(nodes, list):
                for node in nodes:
                    kv = node.get("version", "").lstrip("v").split("-")[0]
                    if kv:
                        all_versions.add(kv)
            addons = k8s.detect_addons()
        except Exception as e:
            logger.warning(f"Could not query in-cluster inventory: {e}")
        return server_version, all_versions, addons

    def scan_cluster(self, db: Session) -> dict:
        server_version, versions_to_check, addons = self._collect_cluster_inventory()
        entries = (
            db.query(CVEEntry)
            .join(CVEFeed)
            .filter(CVEFeed.enabled == True)
            .all()
        )
        node_versions = sorted(versions_to_check - {server_version})
        findings = _match_cves(entries, server_version, node_versions, addons)

        result = CVEScanResult(
            cluster_version=server_version,
            node_versions=node_versions,
            addons=addons,
            total_cves_checked=len(entries),
            affected_count=len(findings),
            findings=findings,
            status="completed",
        )
        db.add(result)
        db.commit()

        return {
            "scanned_at": result.scanned_at.isoformat(),
            "cluster_version": server_version,
            "node_versions": node_versions,
            "addons": addons,
            "total_cves_checked": len(entries),
            "affected_count": len(findings),
            "severity_breakdown": _severity_breakdown(findings),
            "findings": findings,
        }

    def get_latest_scan(self, db: Session) -> Optional[dict]:
        scan = db.query(CVEScanResult).order_by(CVEScanResult.scanned_at.desc()).first()
        if not scan:
            return None
        findings = scan.findings or []
        return {
            "scanned_at": scan.scanned_at.isoformat(),
            "cluster_version": scan.cluster_version,
            "node_versions": scan.node_versions or [],
            "addons": scan.addons or [],
            "total_cves_checked": scan.total_cves_checked,
            "affected_count": scan.affected_count,
            "severity_breakdown": _severity_breakdown(findings),
            "findings": findings,
            "status": scan.status,
        }

    # ── Registered-cluster K8s CVE scan ───────────────────────────────────────

    async def scan_registered_cluster(
        self,
        cluster: ClusterRegistration,
        tenant_id: UUID,
        db: Session,
    ) -> dict:
        """
        Scan a specific registered cluster against all enabled CVE feeds.

        Steps:
          1. Fetch server version + node kubelet versions via the cluster's API server
          2. Detect running add-ons (ingress-nginx, csi-*, coredns, etc.) by scanning
             Deployment and DaemonSet images cluster-wide
          3. Match all CVE entries whose affected_components overlap with found versions
          4. Store result in K8sCVEScanResult and return the summary dict
        """
        client = RemoteK8sClient(cluster)
        scan_result = K8sCVEScanResult(
            cluster_id=cluster.id,
            tenant_id=tenant_id,
            status="running",
        )
        db.add(scan_result)
        db.commit()

        try:
            # Collect cluster inventory
            server_version = await client.get_server_version()
            node_versions = await client.get_node_versions()
            addons = await client.detect_addons()

            # Get all CVEs from enabled feeds
            entries = (
                db.query(CVEEntry)
                .join(CVEFeed)
                .filter(CVEFeed.enabled == True)
                .all()
            )

            findings = _match_cves(entries, server_version, node_versions, addons)

            # Persist result
            scan_result.cluster_version = server_version
            scan_result.node_versions = node_versions
            scan_result.addons = addons
            scan_result.total_cves_checked = len(entries)
            scan_result.affected_count = len(findings)
            scan_result.findings = findings
            scan_result.status = "completed"

            # Update cluster last_seen
            cluster.last_seen = datetime.utcnow()
            db.commit()

            logger.info(
                f"K8s CVE scan [{cluster.name}]: "
                f"{len(findings)} affected / {len(entries)} checked"
            )

        except Exception as exc:
            scan_result.status = "failed"
            scan_result.error = str(exc)
            db.commit()
            logger.error(f"K8s CVE scan [{cluster.name}] failed: {exc}")
            raise

        return self._format_scan_result(scan_result)

    async def scan_all_registered_clusters(self, tenant_id: UUID, db: Session) -> list[dict]:
        """Scan all active clusters for the given tenant."""
        clusters = (
            db.query(ClusterRegistration)
            .filter(
                ClusterRegistration.tenant_id == tenant_id,
                ClusterRegistration.active == True,
            )
            .all()
        )
        results = []
        for cluster in clusters:
            try:
                result = await self.scan_registered_cluster(cluster, tenant_id, db)
                results.append(result)
            except Exception as exc:
                results.append({
                    "cluster_id": str(cluster.id),
                    "cluster_name": cluster.name,
                    "status": "failed",
                    "error": str(exc),
                })
        return results

    def get_latest_cluster_scan(self, cluster_id: UUID, db: Session) -> Optional[dict]:
        scan = (
            db.query(K8sCVEScanResult)
            .filter(K8sCVEScanResult.cluster_id == cluster_id)
            .order_by(K8sCVEScanResult.scanned_at.desc())
            .first()
        )
        if not scan:
            return None
        return self._format_scan_result(scan)

    def get_cluster_scan_history(
        self, cluster_id: UUID, db: Session, limit: int = 20
    ) -> list[dict]:
        scans = (
            db.query(K8sCVEScanResult)
            .filter(K8sCVEScanResult.cluster_id == cluster_id)
            .order_by(K8sCVEScanResult.scanned_at.desc())
            .limit(limit)
            .all()
        )
        return [self._format_scan_result(s) for s in scans]

    @staticmethod
    def _format_scan_result(scan: K8sCVEScanResult) -> dict:
        findings = scan.findings or []
        return {
            "scan_id": str(scan.id),
            "cluster_id": str(scan.cluster_id),
            "scanned_at": scan.scanned_at.isoformat(),
            "cluster_version": scan.cluster_version,
            "node_versions": scan.node_versions or [],
            "addons": scan.addons or [],
            "total_cves_checked": scan.total_cves_checked,
            "affected_count": scan.affected_count,
            "severity_breakdown": _severity_breakdown(findings),
            "findings": findings,
            "status": scan.status,
            "error": scan.error,
        }


# Singleton
cve_service = CVEFeedService()
