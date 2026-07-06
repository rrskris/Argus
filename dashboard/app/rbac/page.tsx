"use client";
import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../../components/AuthContext";
import SeverityBadge from "../../components/SeverityBadge";
import RemediationPanel, { Remediation } from "../../components/RemediationPanel";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ScoreFactor {
    value: unknown;
    weight: number;
    raw_score?: number | null;
}

interface Subject {
    kind: string;
    name: string;
    namespace?: string;
}

interface RBACFinding {
    rule_type: string;
    severity: string;
    title: string;
    description: string;
    role: { kind: string; name: string };
    binding: { kind: string; name: string; namespace: string | null };
    subjects: Subject[];
    contextual_score: number;
    score_factors: Record<string, ScoreFactor>;
    remediation?: Remediation;
}

interface RBACScan {
    scan_id?: string;
    scanned_at: string;
    total_bindings_checked: number;
    affected_count: number;
    severity_breakdown: Record<string, number>;
    findings: RBACFinding[];
    status?: string;
    message?: string;
}

function StatCard({ label, value, color }: { label: string; value: number | string; color: string }) {
    return (
        <div className={`bg-gray-900/80 border ${color} rounded p-4`}>
            <div className="text-2xl font-bold font-mono text-white">{value}</div>
            <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mt-1">{label}</div>
        </div>
    );
}

export default function RBACPage() {
    const { token } = useAuth();
    const [scan, setScan] = useState<RBACScan | null>(null);
    const [scanning, setScanning] = useState(false);
    const [loading, setLoading] = useState(true);
    const [expanded, setExpanded] = useState<number | null>(null);

    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    const loadLatest = useCallback(async () => {
        if (!token) return;
        const res = await fetch(`${API}/rbac/scan/latest`, { headers });
        if (res.ok) setScan(await res.json());
        setLoading(false);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        loadLatest();
    }, [loadLatest]);

    const runScan = async () => {
        setScanning(true);
        const res = await fetch(`${API}/rbac/scan`, { method: "POST", headers });
        if (res.ok) setScan(await res.json());
        setScanning(false);
    };

    const downloadReport = async () => {
        const res = await fetch(`${API}/rbac/scan/latest/report.pdf`, { headers });
        if (!res.ok) {
            alert("No scan results yet — run a scan first.");
            return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "argus-rbac-report.pdf";
        a.click();
        URL.revokeObjectURL(url);
    };

    if (loading) {
        return <div className="p-8 text-center text-gray-500 font-mono animate-pulse py-32">Loading RBAC data...</div>;
    }

    return (
        <div className="p-2">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-3xl font-bold mb-1">RBAC</h1>
                    <p className="text-text-secondary text-sm">
                        Kubernetes Role/ClusterRole misconfigurations, ranked by the same Contextual Risk Score CVE findings use.
                    </p>
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={downloadReport}
                        title="Download the latest scan as a PDF report"
                        className="px-4 py-2 bg-gray-800/60 border border-gray-700 text-gray-300 rounded font-mono text-sm hover:bg-gray-800 transition-colors"
                    >
                        ⬇ Download Report
                    </button>
                    <button
                        onClick={runScan}
                        disabled={scanning}
                        className="px-4 py-2 bg-neon-blue/10 border border-neon-blue text-neon-blue rounded font-mono text-sm hover:bg-neon-blue/20 transition-colors disabled:opacity-50"
                    >
                        {scanning ? "Scanning..." : "Run scan"}
                    </button>
                </div>
            </div>

            {scan && !scan.message && (
                <>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                        <StatCard label="Bindings checked" value={scan.total_bindings_checked} color="border-gray-700" />
                        <StatCard label="Findings" value={scan.affected_count} color="border-red-800/50" />
                        <StatCard label="Critical" value={scan.severity_breakdown.CRITICAL ?? 0} color="border-red-800/50" />
                        <StatCard label="High" value={scan.severity_breakdown.HIGH ?? 0} color="border-orange-800/50" />
                    </div>

                    {scan.findings.length === 0 ? (
                        <div className="text-center py-12 font-mono">
                            <div className="text-3xl mb-3">✓</div>
                            <div className="text-neon-green font-bold">No RBAC misconfigurations found</div>
                            <div className="text-gray-500 text-sm mt-1">{scan.total_bindings_checked} bindings checked</div>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {scan.findings.map((f, i) => (
                                <div key={i} className="border border-gray-800 rounded overflow-hidden">
                                    <button
                                        onClick={() => setExpanded(expanded === i ? null : i)}
                                        className="w-full flex items-center gap-4 px-4 py-3 text-left hover:bg-white/[0.02] transition-colors"
                                    >
                                        <SeverityBadge sev={f.severity} />
                                        <span
                                            className="font-mono text-[11px] px-1.5 py-0.5 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue rounded whitespace-nowrap"
                                            title="Contextual Risk Score"
                                        >
                                            risk {f.contextual_score.toFixed(1)}
                                        </span>
                                        <span className="text-gray-300 text-xs flex-1 truncate">{f.title}</span>
                                        <span className="text-gray-600 text-xs ml-2">{expanded === i ? "▲" : "▼"}</span>
                                    </button>

                                    {expanded === i && (
                                        <div className="border-t border-gray-800 bg-gray-950/60 px-4 py-4 space-y-3 text-xs font-mono">
                                            <p className="text-gray-300 leading-relaxed">{f.description}</p>

                                            <div>
                                                <span className="text-gray-600 uppercase tracking-widest block mb-1">Granted via</span>
                                                <div className="text-gray-400">
                                                    {f.binding.kind} <span className="text-neon-blue">{f.binding.name}</span>
                                                    {f.binding.namespace && <> in namespace <span className="text-neon-blue">{f.binding.namespace}</span></>}
                                                    {" "}→ {f.role.kind} <span className="text-neon-blue">{f.role.name}</span>
                                                </div>
                                            </div>

                                            {f.subjects.length > 0 && (
                                                <div>
                                                    <span className="text-gray-600 uppercase tracking-widest block mb-1">Subjects</span>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {f.subjects.map((s, si) => (
                                                            <span key={si} className="px-1.5 py-0.5 bg-gray-800 border border-gray-700 text-gray-400 text-[10px] rounded">
                                                                {s.kind}: {s.name}{s.namespace ? ` (${s.namespace})` : ""}
                                                            </span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

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

                                            {f.remediation && <RemediationPanel remediation={f.remediation} />}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </>
            )}

            {(!scan || scan.message) && !scanning && (
                <div className="text-center py-16 text-gray-600 font-mono">
                    No scan results yet.{" "}
                    <button onClick={runScan} className="text-neon-blue underline">Run scan now</button>
                </div>
            )}

            {scanning && (
                <div className="text-center py-16 font-mono">
                    <div className="text-neon-blue animate-pulse text-lg mb-2">Scanning RBAC...</div>
                    <div className="text-gray-500 text-sm">Fetching Roles, ClusterRoles, and bindings, then evaluating risk rules.</div>
                </div>
            )}
        </div>
    );
}
