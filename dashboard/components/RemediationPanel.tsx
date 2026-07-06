export interface BenchmarkRef {
    benchmark: string;
    id: string | null;
    title: string;
}

export interface Remediation {
    action: string;
    why_it_matters: string;
    compliance_note: string | null;
    audit_note: string;
    benchmark_refs: BenchmarkRef[];
}

/**
 * Renders a finding's remediation object — the "what to do / why it matters /
 * what it maps to" block shared by the CVE and RBAC finding rows.
 */
export default function RemediationPanel({ remediation }: { remediation: Remediation }) {
    return (
        <div className="space-y-2">
            <div>
                <span className="text-gray-600 uppercase tracking-widest block mb-1">What to do</span>
                <p className="text-neon-green leading-relaxed">{remediation.action}</p>
            </div>
            <div>
                <span className="text-gray-600 uppercase tracking-widest block mb-1">Why it matters</span>
                <p className="text-gray-300 leading-relaxed">{remediation.why_it_matters}</p>
            </div>
            {remediation.benchmark_refs.length > 0 && (
                <div>
                    <span className="text-gray-600 uppercase tracking-widest block mb-1">Benchmark</span>
                    <div className="flex flex-wrap gap-1.5">
                        {remediation.benchmark_refs.map((ref, i) => (
                            <span
                                key={i}
                                className="px-1.5 py-0.5 bg-purple-900/30 border border-purple-700/40 text-purple-300 text-[10px] rounded"
                                title={ref.title}
                            >
                                {ref.benchmark}{ref.id ? ` ${ref.id}` : ""}
                            </span>
                        ))}
                    </div>
                </div>
            )}
            {remediation.compliance_note && (
                <div>
                    <span className="text-gray-600 uppercase tracking-widest block mb-1">Compliance</span>
                    <p className="text-gray-400 leading-relaxed">{remediation.compliance_note}</p>
                </div>
            )}
            <div>
                <span className="text-gray-600 uppercase tracking-widest block mb-1">Audit note</span>
                <p className="text-gray-500 leading-relaxed">{remediation.audit_note}</p>
            </div>
        </div>
    );
}
