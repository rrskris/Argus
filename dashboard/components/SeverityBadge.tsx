export const SEV_STYLE: Record<string, string> = {
    CRITICAL: "bg-red-900/50 text-red-400 border border-red-700/50",
    HIGH:     "bg-orange-900/40 text-orange-400 border border-orange-700/50",
    MEDIUM:   "bg-yellow-900/40 text-yellow-400 border border-yellow-700/50",
    LOW:      "bg-blue-900/40 text-blue-400 border border-blue-700/50",
    UNKNOWN:  "bg-gray-800 text-gray-400 border border-gray-700",
};

export default function SeverityBadge({ sev }: { sev: string }) {
    return (
        <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${SEV_STYLE[sev] ?? SEV_STYLE.UNKNOWN}`}>
            {sev}
        </span>
    );
}
