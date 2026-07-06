"use client";
import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../../components/AuthContext";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ScanContext {
    environment: string;
    data_classification: string;
    compliance_scope: string[];
    exposure: string;
}

const ENVIRONMENTS = ["production", "staging", "dev"];
const DATA_CLASSIFICATIONS = ["public", "internal", "pii", "financial", "phi"];
const EXPOSURES = ["internet-facing", "internal"];
const COMPLIANCE_FRAMEWORKS = ["PCI-DSS", "HIPAA", "SOC2"];

export default function SettingsPage() {
    const { token } = useAuth();
    const [context, setContext] = useState<ScanContext | null>(null);
    const [saving, setSaving] = useState(false);
    const [saved, setSaved] = useState(false);

    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    const loadContext = useCallback(async () => {
        if (!token) return;
        const res = await fetch(`${API}/cve/context`, { headers });
        if (res.ok) setContext(await res.json());
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    useEffect(() => {
        // Kicks off the initial data load for this page, not derived state.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        loadContext();
    }, [loadContext]);

    const saveContext = async (patch: Partial<ScanContext>) => {
        if (!context) return;
        setSaving(true);
        setSaved(false);
        const res = await fetch(`${API}/cve/context`, {
            method: "PUT",
            headers,
            body: JSON.stringify(patch),
        });
        if (res.ok) {
            setContext(await res.json());
            setSaved(true);
        }
        setSaving(false);
    };

    const toggleFramework = (fw: string) => {
        if (!context) return;
        const next = context.compliance_scope.includes(fw)
            ? context.compliance_scope.filter((f) => f !== fw)
            : [...context.compliance_scope, fw];
        saveContext({ compliance_scope: next });
    };

    return (
        <div className="p-2">
            <h1 className="text-3xl font-bold mb-2">Settings</h1>
            <p className="text-text-secondary mb-8">Customize your workspace appearance and preferences.</p>

            <section className="mb-10">
                <h2 className="text-xl font-semibold mb-4 text-primary">Risk Context</h2>
                <div className="bg-card p-6 rounded-lg border border-border-color space-y-6">
                    <p className="text-text-secondary text-sm">
                        Drives the Contextual Risk Score — CVE findings are ranked by what these mean for
                        <em> your</em> cluster, not raw CVSS alone.
                    </p>

                    {!context ? (
                        <p className="text-text-secondary text-sm">Loading...</p>
                    ) : (
                        <>
                            <div>
                                <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-2">Environment</label>
                                <div className="flex gap-2">
                                    {ENVIRONMENTS.map((env) => (
                                        <button key={env}
                                            onClick={() => saveContext({ environment: env })}
                                            className={`px-3 py-1.5 rounded text-sm border transition-colors ${context.environment === env
                                                ? "bg-neon-blue/10 border-neon-blue text-neon-blue"
                                                : "border-border-color text-text-secondary hover:border-neon-blue/50"
                                                }`}
                                        >
                                            {env}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-2">Data classification</label>
                                <div className="flex gap-2 flex-wrap">
                                    {DATA_CLASSIFICATIONS.map((dc) => (
                                        <button key={dc}
                                            onClick={() => saveContext({ data_classification: dc })}
                                            className={`px-3 py-1.5 rounded text-sm border transition-colors ${context.data_classification === dc
                                                ? "bg-neon-blue/10 border-neon-blue text-neon-blue"
                                                : "border-border-color text-text-secondary hover:border-neon-blue/50"
                                                }`}
                                        >
                                            {dc}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-2">Exposure</label>
                                <div className="flex gap-2">
                                    {EXPOSURES.map((exp) => (
                                        <button key={exp}
                                            onClick={() => saveContext({ exposure: exp })}
                                            className={`px-3 py-1.5 rounded text-sm border transition-colors ${context.exposure === exp
                                                ? "bg-neon-blue/10 border-neon-blue text-neon-blue"
                                                : "border-border-color text-text-secondary hover:border-neon-blue/50"
                                                }`}
                                        >
                                            {exp}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div>
                                <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-2">Compliance scope</label>
                                <div className="flex gap-2 flex-wrap">
                                    {COMPLIANCE_FRAMEWORKS.map((fw) => (
                                        <button key={fw}
                                            onClick={() => toggleFramework(fw)}
                                            className={`px-3 py-1.5 rounded text-sm border transition-colors ${context.compliance_scope.includes(fw)
                                                ? "bg-neon-blue/10 border-neon-blue text-neon-blue"
                                                : "border-border-color text-text-secondary hover:border-neon-blue/50"
                                                }`}
                                        >
                                            {fw}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="text-xs text-text-secondary h-4">
                                {saving && "Saving..."}
                                {saved && !saving && "Saved."}
                            </div>
                        </>
                    )}
                </div>
            </section>
        </div>
    );
}
