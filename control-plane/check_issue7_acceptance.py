"""Re-runnable acceptance check for kaaval#7 (CIS 5.1.6 token_automount rule)."""
import json, subprocess, sys, pathlib
cp = pathlib.Path(__file__).parent
fixtures = str(cp.parent / "hack/dev/rbac-fixtures.yaml")

out = subprocess.run(
    [sys.executable, "-m", "app.cli", "scan", "rbac",
     "--manifests", fixtures, "--output", "json"],
    capture_output=True, text=True, cwd=cp)
d = json.loads(out.stdout)
auto = [f for f in d["findings"] if f["rule_type"] == "token_automount"]
sev = {(f.get("workload") or f["service_account"])["name"]: f["severity"] for f in auto}
assert set(sev) == {"default", "token-happy", "override-pod", "override-deploy"}, sev
assert sev == {"default": "MEDIUM", "token-happy": "LOW",
               "override-pod": "MEDIUM", "override-deploy": "MEDIUM"}, sev
kinds = {(f.get("workload") or {}).get("kind") for f in auto if f.get("workload")}
assert kinds == {"Pod", "Deployment"}, kinds

# Round-1 regression: every output mode must survive token findings.
for mode in ("table", "json", "sarif", "junit", "policyreport"):
    r = subprocess.run([sys.executable, "-m", "app.cli", "scan", "rbac",
                        "--manifests", fixtures, "--output", mode],
                       capture_output=True, text=True, cwd=cp)
    assert r.returncode == 0, f"--output {mode} exited {r.returncode}: {r.stderr[-200:]}"

print("acceptance OK:", sev, "| all 5 output modes exit 0")
