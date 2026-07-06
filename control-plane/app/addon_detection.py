"""
Shared add-on image matching — used by both the in-cluster (K8sClient) and
remote (RemoteK8sClient) CVE scan paths to identify running Kubernetes add-ons
by their container image, so both paths can be matched against CVE feed data.

Pure regex matching, no cluster access here — safe to reuse anywhere.
"""

import re
from typing import Optional

# Map from CVE `affected_components[].component` name to image substrings
# that indicate the add-on is running in the cluster.
ADDON_IMAGE_PATTERNS: dict[str, re.Pattern] = {
    "ingress-nginx":   re.compile(r"ingress-nginx/controller", re.IGNORECASE),
    "csi-driver-nfs":  re.compile(r"nfsplugin|nfs-csi|csi-driver-nfs", re.IGNORECASE),
    "csi-driver-smb":  re.compile(r"smbplugin|smb-csi|csi-driver-smb", re.IGNORECASE),
    "metrics-server":  re.compile(r"metrics-server", re.IGNORECASE),
    "coredns":         re.compile(r"coredns", re.IGNORECASE),
}

# Extract image version tag (handles v1.2.3 and 1.2.3 forms)
_IMAGE_VERSION_RE = re.compile(r":v?([\d]+\.[\d]+\.[\d]+)")


def image_version(image: str) -> Optional[str]:
    m = _IMAGE_VERSION_RE.search(image)
    return m.group(1) if m else None


def match_addon(image: str) -> Optional[tuple[str, str]]:
    """Return (addon_name, version) if the image matches a known add-on, else None."""
    for addon_name, pattern in ADDON_IMAGE_PATTERNS.items():
        if pattern.search(image):
            return addon_name, (image_version(image) or "unknown")
    return None
