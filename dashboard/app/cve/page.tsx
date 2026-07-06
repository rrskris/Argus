"use client";
import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../../components/AuthContext";
import SeverityBadge, { SEV_STYLE } from "../../components/SeverityBadge";
import RemediationPanel, { Remediation } from "../../components/RemediationPanel";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Feed {
    id: string; name: string; url: string; feed_type: string;
    description: string | null; enabled: boolean;
    last_fetched: string | null; entry_count: number;
}

interface AffectedMatch {
    component: string; version: string; fixed: string | null;
}

interface ScoreFactor {
    value: unknown;
    weight: number;
    raw_score?: number | null;
}

interface K8sFinding {
    cve_id: string; title: string; severity: string; cvss_score: number | null;
    contextual_score?: number;
    score_factors?: Record<string, ScoreFactor>;
    remediation?: Remediation;
    affected: AffectedMatch[];
    fixed_in: string[] | null; description: string;
    references: { url: string; type: string }[];
    published_date: string | null;
}

interface Addon {
    name: string; version: string; namespace: string; workload: string; image: string;
}

interface ClusterScan {
    scan_id?: string; cluster_id?: string; scanned_at: string;
    cluster_version: string | null; node_versions: string[];
    addons: Addon[]; total_cves_checked: number; affected_count: number;
    severity_breakdown: Record<string, number>; findings: K8sFinding[];
    status?: string; error?: string | null;
}

interface ClusterInfo {
    id: string; name: string; environment: string; active: boolean;
    last_seen: string | null;
    latest_scan: {
        scanned_at: string; cluster_version: string | null;
        affected_count: number; status: string;
        severity_breakdown: Record<string, number>;
    } | null;
}

interface K8sFeedStatus {
    registered: boolean; feed_id?: string; entry_count?: number;
    last_fetched?: string | null; feed_url: string; enabled?: boolean;
}

interface CVEEntry {
    id: string; cve_id: string; title: string; severity: string; cvss_score: number | null;
    published_date: string | null;
    affected_components: { component: string; version?: string }[] | null;
    fixed_in: string[] | null;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SevBar({ breakdown }: { breakdown: Record<string, number> }) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
    const colors = { CRITICAL: "bg-red-500", HIGH: "bg-orange-500", MEDIUM: "bg-yellow-500", LOW: "bg-blue-400" };
    return (
        <div className="flex gap-3 flex-wrap">
            {order.map((s) => (
                <span key={s} className="flex items-center gap-1.5 text-xs font-mono">
                    <span className={`w-2 h-2 rounded-full ${colors[s]}`} />
                    <span className="text-gray-400">{s[0]}{s.slice(1).toLowerCase()}</span>
                    <span className="text-white font-bold">{breakdown[s] ?? 0}</span>
                </span>
            ))}
        </div>
    );
}

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color: string }) {
    return (
        <div className={`bg-gray-900/80 border ${color} rounded p-4`}>
            <div className="text-2xl font-bold font-mono text-white">{value}</div>
            <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mt-1">{label}</div>
            {sub && <div className="text-[10px] text-gray-600 mt-0.5">{sub}</div>}
        </div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CVEPage() {
    const { token } = useAuth();
    const [activeTab, setActiveTab] = useState<"k8s" | "feeds" | "browse">("k8s");

    // K8s scan state
    const [clusters, setClusters] = useState<ClusterInfo[]>([]);
    const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);
    const [clusterScan, setClusterScan] = useState<ClusterScan | null>(null);
    const [scanning, setScanning] = useState(false);
    const [syncingFeed, setSyncingFeed] = useState(false);
    const [k8sFeedStatus, setK8sFeedStatus] = useState<K8sFeedStatus | null>(null);
    const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

    // Feed management state
    const [feeds, setFeeds] = useState<Feed[]>([]);
    const [showAddFeed, setShowAddFeed] = useState(false);
    const [newFeed, setNewFeed] = useState({ name: "", url: "", feed_type: "auto", description: "" });
    const [refreshingFeed, setRefreshingFeed] = useState<string | null>(null);
    const [refreshingAll, setRefreshingAll] = useState(false);

    // CVE browser state
    const [entries, setEntries] = useState<CVEEntry[]>([]);
    const [totalEntries, setTotalEntries] = useState(0);
    const [sevFilter, setSevFilter] = useState("ALL");
    const [searchTerm, setSearchTerm] = useState("");

    const [loading, setLoading] = useState(true);

    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    // ── Data loaders ─────────────────────────────────────────────────────────

    const loadK8sData = useCallback(async () => {
        if (!token) return;
        const [clustersRes, feedRes] = await Promise.all([
            fetch(`${API}/cve/k8s/clusters`, { headers }),
            fetch(`${API}/cve/k8s/feed`, { headers }),
        ]);
        if (clustersRes.ok) {
            const d = await clustersRes.json();
            setClusters(d.clusters ?? []);
            // Auto-select first cluster
            if ((d.clusters ?? []).length > 0 && !selectedClusterId) {
                setSelectedClusterId(d.clusters[0].id);
            }
        }
        if (feedRes.ok) setK8sFeedStatus(await feedRes.json());
    }, [token, selectedClusterId]);

    const loadClusterScan = useCallback(async (clusterId: string) => {
        if (!token || !clusterId) return;
        const res = await fetch(`${API}/cve/k8s/clusters/${clusterId}/scan/latest`, { headers });
        if (res.ok) {
            const d = await res.json();
            if (d.findings) setClusterScan(d);
            else setClusterScan(null);
        }
    }, [token]);

    // Free, self-scan path — scans the cluster Argus is running in (no cluster
    // registration required). This is the primary v1 detector flow.
    const loadSelfScan = useCallback(async () => {
        if (!token) return;
        const res = await fetch(`${API}/cve/scan/latest`, { headers });
        if (res.ok) {
            const d = await res.json();
            if (d.findings) setClusterScan(d);
        }
    }, [token]);

    const loadFeeds = useCallback(async () => {
        if (!token) return;
        const res = await fetch(`${API}/cve/feeds`, { headers });
        if (res.ok) setFeeds(await res.json());
    }, [token]);

    const loadEntries = useCallback(async (sev = sevFilter, q = searchTerm) => {
        if (!token) return;
        const params = new URLSearchParams({ limit: "50" });
        if (sev !== "ALL") params.set("severity", sev);
        if (q) params.set("search", q);
        const res = await fetch(`${API}/cve/entries?${params}`, { headers });
        if (res.ok) {
            const d = await res.json();
            setEntries(d.entries ?? []);
            setTotalEntries(d.total ?? 0);
        }
    }, [token, sevFilter, searchTerm]);

    useEffect(() => {
        if (!token) return;
        // Kicks off the initial data load for this page, not derived state.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setLoading(true);
        Promise.all([loadK8sData(), loadFeeds(), loadEntries(), loadSelfScan()]).finally(() => setLoading(false));
    }, [token]);

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        if (selectedClusterId) loadClusterScan(selectedClusterId);
    }, [selectedClusterId]);

    // ── Actions ──────────────────────────────────────────────────────────────

    const syncK8sFeed = async () => {
        setSyncingFeed(true);
        try {
            const res = await fetch(`${API}/cve/k8s/feed/sync`, { method: "POST", headers });
            if (res.ok) {
                await loadK8sData();
                await loadFeeds();
                await loadEntries();
            }
        } finally { setSyncingFeed(false); }
    };

    const runClusterScan = async () => {
        if (!selectedClusterId) return;
        setScanning(true);
        setClusterScan(null);
        try {
            const res = await fetch(`${API}/cve/k8s/clusters/${selectedClusterId}/scan`, {
                method: "POST", headers,
            });
            if (res.ok) {
                const d = await res.json();
                setClusterScan(d);
                await loadK8sData(); // refresh summary badges
            } else {
                const err = await res.json();
                alert(`Scan failed: ${err.detail ?? "Unknown error"}`);
            }
        } finally { setScanning(false); }
    };

    const runSelfScan = async () => {
        setScanning(true);
        setClusterScan(null);
        try {
            const res = await fetch(`${API}/cve/scan`, { method: "POST", headers });
            if (res.ok) {
                setClusterScan(await res.json());
            } else {
                const err = await res.json();
                alert(`Scan failed: ${err.detail ?? "Unknown error"}`);
            }
        } finally { setScanning(false); }
    };

    // Primary v1 action: scan the cluster Argus runs in unless a registered
    // (EE) cluster is selected, in which case scan that one instead.
    const runScan = () => (selectedClusterId ? runClusterScan() : runSelfScan());

    const downloadReport = async () => {
        const res = await fetch(`${API}/cve/scan/latest/report.pdf`, { headers });
        if (!res.ok) {
            alert("No scan results yet — run a scan first.");
            return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "argus-cve-report.pdf";
        a.click();
        URL.revokeObjectURL(url);
    };

    const refreshFeed = async (id: string) => {
        setRefreshingFeed(id);
        try {
            await fetch(`${API}/cve/feeds/${id}/refresh`, { method: "POST", headers });
            await loadFeeds();
        } finally { setRefreshingFeed(null); }
    };

    const refreshAll = async () => {
        setRefreshingAll(true);
        try {
            await fetch(`${API}/cve/feeds/refresh-all`, { method: "POST", headers });
            await Promise.all([loadFeeds(), loadEntries()]);
        } finally { setRefreshingAll(false); }
    };

    const toggleFeed = async (id: string) => {
        await fetch(`${API}/cve/feeds/${id}/toggle`, { method: "PATCH", headers });
        await loadFeeds();
    };

    const deleteFeed = async (id: string, name: string) => {
        if (!confirm(`Delete feed "${name}" and all its CVE entries?`)) return;
        await fetch(`${API}/cve/feeds/${id}`, { method: "DELETE", headers });
        await Promise.all([loadFeeds(), loadEntries()]);
    };

    const addFeed = async () => {
        if (!newFeed.name || !newFeed.url) return;
        const res = await fetch(`${API}/cve/feeds`, {
            method: "POST", headers,
            body: JSON.stringify(newFeed),
        });
        if (res.ok) {
            setNewFeed({ name: "", url: "", feed_type: "auto", description: "" });
            setShowAddFeed(false);
            await loadFeeds();
        } else {
            const err = await res.json();
            alert(err.detail ?? "Failed to add feed");
        }
    };

    if (loading) {
        return <div className="p-8 text-center text-gray-500 font-mono animate-pulse py-32">Loading CVE data...</div>;
    }

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-mono tracking-tight text-white">K8s CVE Scanner</h1>
                    <p className="text-gray-500 text-sm mt-1 font-mono">
                        Official Kubernetes CVE feed · per-cluster vulnerability detection
                    </p>
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={syncK8sFeed}
                        disabled={syncingFeed}
                        title="Fetch latest entries from kubernetes.io official CVE feed"
                        className="px-4 py-2 text-xs font-mono uppercase tracking-widest border border-neon-green/30 text-neon-green/70 hover:text-neon-green hover:border-neon-green/60 rounded transition-colors disabled:opacity-50"
                    >
                        {syncingFeed ? "Syncing..." : "↓ Sync K8s Feed"}
                    </button>
                    <button
                        onClick={runScan}
                        disabled={scanning}
                        className="px-4 py-2 text-xs font-mono uppercase tracking-widest bg-neon-blue/10 border border-neon-blue/40 text-neon-blue hover:bg-neon-blue/20 rounded transition-colors disabled:opacity-50"
                    >
                        {scanning ? "Scanning..." : "▶ Scan Cluster"}
                    </button>
                    <button
                        onClick={downloadReport}
                        disabled={!clusterScan}
                        title="Download the latest scan as a PDF report"
                        className="px-4 py-2 text-xs font-mono uppercase tracking-widest border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded transition-colors disabled:opacity-50"
                    >
                        ⬇ Download Report
                    </button>
                </div>
            </div>

            {/* K8s feed status strip */}
            <div className="bg-gray-900/60 border border-gray-800 rounded px-4 py-3 flex flex-wrap items-center gap-6 text-xs font-mono">
                <div>
                    <span className="text-gray-500 uppercase tracking-widest">K8s CVE Feed </span>
                    {k8sFeedStatus?.registered ? (
                        <span className="text-neon-green">● Active</span>
                    ) : (
                        <span className="text-gray-600">○ Not synced</span>
                    )}
                </div>
                {k8sFeedStatus?.registered && (
                    <>
                        <div><span className="text-gray-500">CVEs loaded </span><span className="text-white">{k8sFeedStatus.entry_count ?? 0}</span></div>
                        <div><span className="text-gray-500">Last sync </span><span className="text-gray-300">{k8sFeedStatus.last_fetched ? new Date(k8sFeedStatus.last_fetched).toLocaleString() : "—"}</span></div>
                    </>
                )}
                {!k8sFeedStatus?.registered && (
                    <span className="text-yellow-600">Click &quot;Sync K8s Feed&quot; to load the official Kubernetes CVE database.</span>
                )}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-gray-800">
                {([
                    ["k8s",    "Cluster Scan"],
                    ["feeds",  "CVE Feeds"],
                    ["browse", "CVE Database"],
                ] as const).map(([t, label]) => (
                    <button
                        key={t}
                        onClick={() => setActiveTab(t)}
                        className={`px-5 py-2.5 text-xs font-mono uppercase tracking-widest border-b-2 transition-colors ${
                            activeTab === t
                                ? "border-neon-blue text-neon-blue"
                                : "border-transparent text-gray-500 hover:text-gray-300"
                        }`}
                    >
                        {label}
                    </button>
                ))}
            </div>

            {/* ── TAB: Cluster Scan ─────────────────────────────────────────────── */}
            {activeTab === "k8s" && (
                <div className="space-y-5">
                    {/* Cluster picker — only relevant once additional clusters are registered */}
                    {clusters.length > 0 && (
                        <div className="flex items-center gap-4 flex-wrap">
                            <label className="text-xs font-mono text-gray-500 uppercase tracking-widest">Cluster</label>
                            <div className="flex gap-2 flex-wrap">
                                {clusters.map((c) => (
                                    <button
                                        key={c.id}
                                        onClick={() => setSelectedClusterId(c.id)}
                                        className={`px-3 py-1.5 text-xs font-mono rounded border transition-colors ${
                                            selectedClusterId === c.id
                                                ? "border-neon-blue bg-neon-blue/10 text-neon-blue"
                                                : "border-gray-700 text-gray-400 hover:border-gray-500"
                                        }`}
                                    >
                                        {c.name}
                                        <span className={`ml-1.5 text-[10px] ${c.active ? "text-neon-green" : "text-gray-600"}`}>
                                            {c.environment}
                                        </span>
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Cluster scan summary */}
                    {clusterScan && (
                                <div className="space-y-4">
                                    {/* Info bar */}
                                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                                        <StatCard
                                            label="Cluster Version"
                                            value={clusterScan.cluster_version ?? "—"}
                                            color="border-neon-blue/30"
                                        />
                                        <StatCard
                                            label="Affected CVEs"
                                            value={clusterScan.affected_count}
                                            sub={`of ${clusterScan.total_cves_checked} checked`}
                                            color={clusterScan.affected_count > 0 ? "border-red-800/50" : "border-neon-green/30"}
                                        />
                                        <StatCard
                                            label="Add-ons Detected"
                                            value={clusterScan.addons.length}
                                            color="border-gray-700/50"
                                        />
                                        <div className="bg-gray-900/80 border border-gray-700/50 rounded p-4">
                                            <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-2">Severity</div>
                                            <SevBar breakdown={clusterScan.severity_breakdown} />
                                        </div>
                                    </div>

                                    {/* Cluster details */}
                                    <div className="bg-gray-900/60 border border-gray-800 rounded px-4 py-3 flex flex-wrap gap-6 text-xs font-mono">
                                        {clusterScan.node_versions.length > 0 && (
                                            <div>
                                                <span className="text-gray-500 uppercase tracking-widest">Node Kubelet Versions </span>
                                                <span className="text-gray-300">{clusterScan.node_versions.join(", ")}</span>
                                            </div>
                                        )}
                                        {clusterScan.addons.length > 0 && (
                                            <div>
                                                <span className="text-gray-500 uppercase tracking-widest">Add-ons </span>
                                                {clusterScan.addons.map((a) => (
                                                    <span key={`${a.name}-${a.version}`}
                                                        className="inline-block mr-2 px-1.5 py-0.5 bg-gray-800 border border-gray-700 text-gray-300 rounded text-[10px]"
                                                        title={`${a.workload} (${a.namespace})\n${a.image}`}
                                                    >
                                                        {a.name} v{a.version}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                        <div className="ml-auto">
                                            <span className="text-gray-500">Scanned </span>
                                            <span className="text-gray-300">{new Date(clusterScan.scanned_at).toLocaleString()}</span>
                                        </div>
                                    </div>

                                    {/* Findings table */}
                                    {clusterScan.findings.length === 0 ? (
                                        <div className="text-center py-12 font-mono">
                                            <div className="text-3xl mb-3">✓</div>
                                            <div className="text-neon-green font-bold">No matching CVEs found</div>
                                            <div className="text-gray-500 text-sm mt-1">{clusterScan.total_cves_checked} CVEs checked against Kubernetes {clusterScan.cluster_version}</div>
                                        </div>
                                    ) : (
                                        <div className="space-y-2">
                                            {clusterScan.findings.map((f) => (
                                                <div key={f.cve_id} className="border border-gray-800 rounded overflow-hidden">
                                                    {/* Row header */}
                                                    <button
                                                        onClick={() => setExpandedFinding(expandedFinding === f.cve_id ? null : f.cve_id)}
                                                        className="w-full flex items-center gap-4 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors"
                                                    >
                                                        <span className="font-mono text-neon-blue text-sm whitespace-nowrap">{f.cve_id}</span>
                                                        <SeverityBadge sev={f.severity} />
                                                        <span className="font-mono text-gray-300 text-xs">{f.cvss_score?.toFixed(1) ?? "—"}</span>
                                                        {f.contextual_score !== undefined && (
                                                            <span
                                                                className="font-mono text-[11px] px-1.5 py-0.5 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue rounded whitespace-nowrap"
                                                                title="Contextual Risk Score — severity weighted by environment, data classification, compliance scope, and exposure"
                                                            >
                                                                risk {f.contextual_score.toFixed(1)}
                                                            </span>
                                                        )}
                                                        <span className="text-gray-300 text-xs flex-1 truncate">{f.title}</span>
                                                        {/* Affected component chips */}
                                                        <div className="flex gap-1 flex-shrink-0">
                                                            {f.affected.map((a, i) => (
                                                                <span key={i}
                                                                    className="px-1.5 py-0.5 bg-red-900/30 border border-red-800/40 text-red-400 text-[10px] font-mono rounded"
                                                                    title={`fixed in ${a.fixed ?? "unknown"}`}
                                                                >
                                                                    {a.component} {a.version}
                                                                </span>
                                                            ))}
                                                        </div>
                                                        <span className="text-gray-600 text-xs ml-2">{expandedFinding === f.cve_id ? "▲" : "▼"}</span>
                                                    </button>

                                                    {/* Expanded detail */}
                                                    {expandedFinding === f.cve_id && (
                                                        <div className="border-t border-gray-800 bg-gray-950/60 px-4 py-4 space-y-3 text-xs font-mono">
                                                            <p className="text-gray-300 leading-relaxed">{f.description}</p>
                                                            {f.score_factors && (
                                                                <div>
                                                                    <span className="text-gray-600 uppercase tracking-widest block mb-1">Why it&apos;s ranked here</span>
                                                                    <div className="flex flex-wrap gap-1.5">
                                                                        {Object.entries(f.score_factors)
                                                                            .filter(([, factor]) => factor.weight > 1.0)
                                                                            .map(([key, factor]) => (
                                                                                <span key={key}
                                                                                    className="px-1.5 py-0.5 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue text-[10px] rounded"
                                                                                >
                                                                                    {key.replace(/_/g, " ")}: {String(factor.value)} (&times;{factor.weight})
                                                                                </span>
                                                                            ))}
                                                                        {Object.values(f.score_factors).every((factor) => factor.weight <= 1.0) && (
                                                                            <span className="text-gray-600">
                                                                                No elevated risk factors set — configure environment/data classification/exposure in Settings.
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {f.remediation && <RemediationPanel remediation={f.remediation} />}
                                                            <div className="flex flex-wrap gap-4 text-gray-500">
                                                                {f.fixed_in && f.fixed_in.length > 0 && (
                                                                    <div>
                                                                        <span className="text-gray-600 uppercase tracking-widest">Fixed in </span>
                                                                        <span className="text-neon-green">{f.fixed_in.join(", ")}</span>
                                                                    </div>
                                                                )}
                                                                {f.published_date && (
                                                                    <div>
                                                                        <span className="text-gray-600 uppercase tracking-widest">Published </span>
                                                                        <span className="text-gray-400">{new Date(f.published_date).toLocaleDateString()}</span>
                                                                    </div>
                                                                )}
                                                            </div>
                                                            {/* Affected component breakdown */}
                                                            <div>
                                                                <span className="text-gray-600 uppercase tracking-widest block mb-1">Affected in your cluster</span>
                                                                {f.affected.map((a, i) => (
                                                                    <div key={i} className="flex gap-3 items-center text-[11px]">
                                                                        <span className="text-red-400">{a.component}</span>
                                                                        <span className="text-gray-500">running</span>
                                                                        <span className="text-red-300 font-bold">v{a.version}</span>
                                                                        {a.fixed && <>
                                                                            <span className="text-gray-600">→ fix at</span>
                                                                            <span className="text-neon-green">v{a.fixed}</span>
                                                                        </>}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                            {/* References */}
                                                            {f.references.length > 0 && (
                                                                <div className="flex gap-3 flex-wrap">
                                                                    {f.references.map((r, i) => (
                                                                        <a key={i} href={r.url} target="_blank" rel="noreferrer"
                                                                            className="text-neon-blue/70 hover:text-neon-blue underline">
                                                                            {r.type === "ADVISORY" ? "Advisory" : "Reference"} ↗
                                                                        </a>
                                                                    ))}
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                    {!clusterScan && !scanning && (
                        <div className="text-center py-16 text-gray-600 font-mono">
                            No scan results yet.{" "}
                            <button onClick={runScan} className="text-neon-blue underline">Run scan now</button>
                        </div>
                    )}

                    {scanning && (
                        <div className="text-center py-16 font-mono">
                            <div className="text-neon-blue animate-pulse text-lg mb-2">Scanning cluster...</div>
                            <div className="text-gray-500 text-sm">
                                Detecting Kubernetes version, node kubelet versions, and running add-ons,
                                then matching against {k8sFeedStatus?.entry_count ?? "all"} CVEs.
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── TAB: CVE Feeds ──────────────────────────────────────────────────── */}
            {activeTab === "feeds" && (
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-sm font-mono uppercase tracking-widest text-gray-400">Configured Feeds</h2>
                        <div className="flex gap-2">
                            <button
                                onClick={refreshAll}
                                disabled={refreshingAll}
                                className="px-3 py-1.5 text-xs font-mono uppercase tracking-widest border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded transition-colors disabled:opacity-50"
                            >
                                {refreshingAll ? "Refreshing..." : "Refresh All"}
                            </button>
                            <button
                                onClick={() => setShowAddFeed(!showAddFeed)}
                                className="text-xs font-mono uppercase tracking-widest text-neon-blue/70 hover:text-neon-blue border border-neon-blue/20 hover:border-neon-blue/50 px-3 py-1.5 rounded transition-colors"
                            >
                                {showAddFeed ? "Cancel" : "+ Add Feed"}
                            </button>
                        </div>
                    </div>

                    {showAddFeed && (
                        <div className="bg-gray-900/80 border border-gray-700/60 rounded p-4 space-y-3">
                            <p className="text-xs text-gray-500 font-mono">
                                Supports: JSON Feed 1.0 (Kubernetes official, with embedded OSV extraction), OSV (osv.dev), NVD JSON 2.0
                            </p>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {[
                                    { key: "name", placeholder: "Feed name *" },
                                    { key: "url", placeholder: "Feed URL *" },
                                    { key: "description", placeholder: "Description (optional)" },
                                ].map(({ key, placeholder }) => (
                                    <input key={key}
                                        placeholder={placeholder}
                                        value={newFeed[key as keyof typeof newFeed]}
                                        onChange={(e) => setNewFeed({ ...newFeed, [key]: e.target.value })}
                                        className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/50"
                                    />
                                ))}
                                <select
                                    value={newFeed.feed_type}
                                    onChange={(e) => setNewFeed({ ...newFeed, feed_type: e.target.value })}
                                    className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 focus:outline-none focus:border-neon-blue/50"
                                >
                                    <option value="auto">Auto-detect format</option>
                                    <option value="json_feed">JSON Feed 1.0 (k8s official)</option>
                                    <option value="osv">OSV (osv.dev)</option>
                                    <option value="nvd">NVD JSON 2.0</option>
                                </select>
                            </div>
                            <button onClick={addFeed}
                                className="px-4 py-2 text-xs font-mono uppercase tracking-widest bg-neon-blue/10 border border-neon-blue/40 text-neon-blue hover:bg-neon-blue/20 rounded transition-colors"
                            >
                                Add Feed
                            </button>
                        </div>
                    )}

                    <div className="overflow-x-auto rounded border border-gray-800">
                        <table className="w-full text-sm font-mono">
                            <thead className="bg-gray-900 text-gray-500 text-[11px] uppercase tracking-widest">
                                <tr>
                                    <th className="px-4 py-3 text-left">Feed Name</th>
                                    <th className="px-4 py-3 text-left">Type</th>
                                    <th className="px-4 py-3 text-left">CVEs</th>
                                    <th className="px-4 py-3 text-left">Last Refreshed</th>
                                    <th className="px-4 py-3 text-left">Status</th>
                                    <th className="px-4 py-3 text-left">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/50">
                                {feeds.length === 0 ? (
                                    <tr><td colSpan={6} className="text-center py-12 text-gray-600">No feeds configured. Use &quot;Sync K8s Feed&quot; or &quot;Add Feed&quot; to get started.</td></tr>
                                ) : feeds.map((f) => (
                                    <tr key={f.id} className="hover:bg-white/[0.02] transition-colors">
                                        <td className="px-4 py-3">
                                            <div className="text-gray-200">{f.name}</div>
                                            <div className="text-gray-600 text-[10px] truncate max-w-xs" title={f.url}>{f.url}</div>
                                        </td>
                                        <td className="px-4 py-3 text-gray-400 text-[11px] uppercase">{f.feed_type}</td>
                                        <td className="px-4 py-3 text-gray-300">{f.entry_count}</td>
                                        <td className="px-4 py-3 text-gray-500 text-[11px]">
                                            {f.last_fetched ? new Date(f.last_fetched).toLocaleString() : "Never"}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-flex items-center gap-1.5 text-[11px] ${f.enabled ? "text-neon-green" : "text-gray-600"}`}>
                                                <span className={`w-1.5 h-1.5 rounded-full ${f.enabled ? "bg-neon-green" : "bg-gray-600"}`} />
                                                {f.enabled ? "Active" : "Disabled"}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex gap-3">
                                                <button onClick={() => refreshFeed(f.id)} disabled={refreshingFeed === f.id}
                                                    className="text-[11px] text-neon-blue/70 hover:text-neon-blue disabled:opacity-40 transition-colors">
                                                    {refreshingFeed === f.id ? "..." : "Refresh"}
                                                </button>
                                                <button onClick={() => toggleFeed(f.id)}
                                                    className="text-[11px] text-gray-500 hover:text-yellow-400 transition-colors">
                                                    {f.enabled ? "Disable" : "Enable"}
                                                </button>
                                                <button onClick={() => deleteFeed(f.id, f.name)}
                                                    className="text-[11px] text-gray-600 hover:text-red-400 transition-colors">
                                                    Delete
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ── TAB: CVE Database ───────────────────────────────────────────────── */}
            {activeTab === "browse" && (
                <div className="space-y-4">
                    <div className="flex flex-wrap gap-3 items-center">
                        <input
                            type="text"
                            placeholder="Search CVE ID or title..."
                            value={searchTerm}
                            onChange={(e) => { setSearchTerm(e.target.value); loadEntries(sevFilter, e.target.value); }}
                            className="bg-gray-900 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/60 w-64"
                        />
                        <div className="flex gap-1">
                            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                                <button key={s}
                                    onClick={() => { setSevFilter(s); loadEntries(s, searchTerm); }}
                                    className={`px-3 py-1.5 text-[11px] font-mono uppercase tracking-wider rounded transition-colors border ${
                                        sevFilter === s
                                            ? (SEV_STYLE[s] ?? "bg-gray-700 text-white border-gray-500")
                                            : "bg-transparent text-gray-500 border-gray-700 hover:border-gray-500"
                                    }`}
                                >
                                    {s}
                                </button>
                            ))}
                        </div>
                        <span className="text-gray-600 text-xs font-mono ml-auto">{totalEntries} total</span>
                    </div>

                    <div className="overflow-x-auto rounded border border-gray-800">
                        <table className="w-full text-sm font-mono">
                            <thead className="bg-gray-900 text-gray-500 text-[11px] uppercase tracking-widest">
                                <tr>
                                    <th className="px-4 py-3 text-left">CVE ID</th>
                                    <th className="px-4 py-3 text-left">Severity</th>
                                    <th className="px-4 py-3 text-left">CVSS</th>
                                    <th className="px-4 py-3 text-left">Title</th>
                                    <th className="px-4 py-3 text-left">Affected</th>
                                    <th className="px-4 py-3 text-left">Published</th>
                                    <th className="px-4 py-3 text-left">Fixed In</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/50">
                                {entries.length === 0 ? (
                                    <tr><td colSpan={7} className="text-center py-12 text-gray-600">No CVE entries found. Sync the K8s feed or refresh feeds to load data.</td></tr>
                                ) : entries.map((e) => (
                                    <tr key={e.id} className="hover:bg-white/[0.02] transition-colors">
                                        <td className="px-4 py-3 text-neon-blue whitespace-nowrap">{e.cve_id}</td>
                                        <td className="px-4 py-3"><SeverityBadge sev={e.severity} /></td>
                                        <td className="px-4 py-3 text-gray-300">{e.cvss_score?.toFixed(1) ?? "—"}</td>
                                        <td className="px-4 py-3 text-gray-300 max-w-sm truncate" title={e.title}>{e.title}</td>
                                        <td className="px-4 py-3">
                                            {(e.affected_components ?? []).slice(0, 2).map((c, i) => (
                                                <span key={i} className="inline-block mr-1 px-1 py-0.5 bg-gray-800 border border-gray-700 text-gray-400 text-[10px] rounded">
                                                    {c.component}
                                                </span>
                                            ))}
                                        </td>
                                        <td className="px-4 py-3 text-gray-500 text-[11px]">
                                            {e.published_date ? new Date(e.published_date).toLocaleDateString() : "—"}
                                        </td>
                                        <td className="px-4 py-3 text-gray-500 text-[11px]">
                                            {e.fixed_in?.join(", ") ?? "—"}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
