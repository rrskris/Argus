"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "../components/AuthContext";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface LatestScan {
    scanned_at: string;
    cluster_version: string | null;
    affected_count: number;
    total_cves_checked: number;
    severity_breakdown: Record<string, number>;
    status?: string;
}

interface Summary {
    feeds: number;
    total_cves: number;
    severity_breakdown: Record<string, number>;
    latest_scan: LatestScan | { message: string } | null;
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

export default function HomePage() {
    const { token, user } = useAuth();
    const [summary, setSummary] = useState<Summary | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (!token) return;
        fetch(`${API}/cve/summary`, { headers: { Authorization: `Bearer ${token}` } })
            .then((r) => r.json())
            .then(setSummary)
            .finally(() => setLoading(false));
    }, [token]);

    if (loading) {
        return <div className="p-8 text-center text-gray-500 font-mono animate-pulse py-32">Loading dashboard...</div>;
    }

    const latestScan =
        summary?.latest_scan && "scanned_at" in summary.latest_scan
            ? (summary.latest_scan as LatestScan)
            : null;

    return (
        <div className="p-6 space-y-6">
            <div>
                <h1 className="text-3xl font-bold font-mono tracking-tight text-white">
                    Welcome{user?.username ? `, ${user.username}` : ""}
                </h1>
                <p className="text-gray-500 text-sm mt-1 font-mono">
                    Argus &mdash; Kubernetes CVE detector &amp; report generator
                </p>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <StatCard label="Feeds Configured" value={summary?.feeds ?? 0} color="border-gray-700/50" />
                <StatCard label="CVEs Tracked" value={summary?.total_cves ?? 0} color="border-gray-700/50" />
                <StatCard
                    label="Affected (Latest Scan)"
                    value={latestScan?.affected_count ?? "—"}
                    sub={latestScan ? `of ${latestScan.total_cves_checked} checked` : "no scan yet"}
                    color={latestScan && latestScan.affected_count > 0 ? "border-red-800/50" : "border-neon-green/30"}
                />
                <StatCard
                    label="Cluster Version"
                    value={latestScan?.cluster_version ?? "—"}
                    color="border-neon-blue/30"
                />
            </div>

            <div className="bg-gray-900/80 border border-gray-700/50 rounded p-4">
                <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-2">
                    Severity Breakdown {latestScan ? "(Latest Scan)" : "(All Tracked CVEs)"}
                </div>
                <SevBar breakdown={(latestScan?.severity_breakdown ?? summary?.severity_breakdown) ?? {}} />
            </div>

            <div className="flex gap-3">
                <Link
                    href="/cve"
                    className="px-4 py-2 text-xs font-mono uppercase tracking-widest bg-neon-blue/10 border border-neon-blue/40 text-neon-blue hover:bg-neon-blue/20 rounded transition-colors"
                >
                    {latestScan ? "View Full Report →" : "Run Your First Scan →"}
                </Link>
            </div>
        </div>
    );
}
