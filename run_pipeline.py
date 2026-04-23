"""
DevSecOps Threat Detection Pipeline — Single Entry Point
Run this file to scan, generate the HTML report, and open it in your browser.

Usage:
    python run_pipeline.py
"""

import subprocess
import json
import os
import webbrowser
from datetime import datetime


# ── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))
TARGET_FILE = os.path.join(ROOT_DIR, "pipeline", "code vulnerable_app.py")
REPORT_FILE = os.path.join(ROOT_DIR, "reports", "threat_report.html")


# ── Scan Functions ────────────────────────────────────────────────────────────
def run_bandit(target_file):
    print("[*] Running Bandit (Static Analysis)...")
    result = subprocess.run(
        ["bandit", "-f", "json", target_file],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("    [!] Bandit returned no output — is it installed? (pip install bandit)")
        return {}


def run_detect_secrets(target_file):
    print("[*] Running detect-secrets (Secret Scanner)...")
    result = subprocess.run(
        ["detect-secrets", "scan", target_file],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("    [!] detect-secrets returned no output — is it installed? (pip install detect-secrets)")
        return {}


def run_pip_audit():
    print("[*] Running pip-audit (Dependency Check)...")
    result = subprocess.run(
        ["pip-audit", "--format", "json"],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("    [!] pip-audit returned no output — is it installed? (pip install pip-audit)")
        return {}


# ── STRIDE Mapping ────────────────────────────────────────────────────────────
def map_to_stride(issue_type):
    stride_map = {
        "hardcoded_password_string": "Information Disclosure",
        "hardcoded_sql_expressions": "Tampering",
        "Secret Keyword":            "Information Disclosure",
        "CVE":                       "Tampering",
        "B105":                      "Information Disclosure",
        "B608":                      "Tampering",
        "B106":                      "Information Disclosure",
        "B107":                      "Information Disclosure",
    }
    for key in stride_map:
        if key.lower() in issue_type.lower():
            return stride_map[key]
    return "Unknown"


# ── Recommendations ───────────────────────────────────────────────────────────
def get_recommendation(title, tool):
    title_lower = title.lower()
    if "b105" in title_lower or "hardcoded_password" in title_lower:
        return "Remove hardcoded password. Store credentials in environment variables using os.environ or a secrets manager such as python-dotenv or AWS Secrets Manager."
    if "b608" in title_lower or "sql" in title_lower:
        return "Replace string-concatenated queries with parameterised queries. Use cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)) to prevent SQL injection."
    if "b106" in title_lower or "b107" in title_lower:
        return "Avoid passing credentials as function arguments. Use environment variables or a secure vault instead."
    if "secret keyword" in title_lower:
        return "Remove the hardcoded secret from source code. Use environment variables (os.environ) or a secrets manager. Rotate the exposed key immediately."
    if "cve-2025-8869" in title_lower or "cve-2026-1703" in title_lower:
        return "Upgrade pip to the latest version: pip install --upgrade pip"
    if "cve-2026-4539" in title_lower:
        return "Upgrade Pygments to version 2.20.0 or later: pip install --upgrade pygments"
    if "cve" in title_lower:
        return "Run pip install --upgrade <package> for the affected dependency. Check the CVE advisory for the minimum safe version."
    return "Review the finding and apply the recommended mitigation from the OWASP guidelines."


# ── HTML Report Generator ─────────────────────────────────────────────────────
def severity_color(severity):
    return {
        "HIGH":     "#e74c3c",
        "MEDIUM":   "#e67e22",
        "LOW":      "#f1c40f",
        "CRITICAL": "#8e44ad",
    }.get(severity.upper(), "#95a5a6")


def generate_report(findings, output_file):
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high   = sum(1 for f in findings if f["severity"].upper() == "HIGH")
    medium = sum(1 for f in findings if f["severity"].upper() == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"].upper() == "LOW")

    rows = ""
    for i, f in enumerate(findings, 1):
        color = severity_color(f["severity"])
        rec   = get_recommendation(f["title"], f["tool"])
        rows += f"""
        <tr>
            <td>{i}</td>
            <td><span style="background:{color};color:white;padding:3px 8px;
                border-radius:4px;font-size:12px">{f["severity"].upper()}</span></td>
            <td>{f["title"]}</td>
            <td>{f["tool"]}</td>
            <td><span style="background:#2980b9;color:white;padding:3px 8px;
                border-radius:4px;font-size:12px">{f["stride"]}</span></td>
            <td>Line {f["line"]}</td>
            <td>{f["description"][:100]}</td>
            <td class="rec">{rec}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 5px 0 0; opacity: 0.8; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h2 {{ margin: 0; font-size: 36px; }}
        .card p {{ margin: 5px 0 0; color: #666; }}
        .total  {{ border-top: 4px solid #2c3e50; }}
        .high   {{ border-top: 4px solid #e74c3c; }}
        .medium {{ border-top: 4px solid #e67e22; }}
        .low    {{ border-top: 4px solid #f1c40f; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; font-size: 13px; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; font-size: 13px; vertical-align: top; }}
        td.rec {{ color: #2c3e50; font-style: italic; font-size: 12px; }}
        tr:hover {{ background: #f9f9f9; }}
        .footer {{ text-align: center; margin-top: 30px; color: #999; font-size: 12px; }}
        .methodology {{ background: white; padding: 20px; border-radius: 8px;
                        margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .methodology h3 {{ color: #2c3e50; margin-top: 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DevSecOps Threat Detection Report</h1>
        <p>Project: Secure App Pipeline &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; Methodology: OWASP STRIDE</p>
    </div>

    <div class="summary">
        <div class="card total"><h2>{len(findings)}</h2><p>Total Findings</p></div>
        <div class="card high"><h2 style="color:#e74c3c">{high}</h2><p>High Severity</p></div>
        <div class="card medium"><h2 style="color:#e67e22">{medium}</h2><p>Medium Severity</p></div>
        <div class="card low"><h2 style="color:#f1c40f">{low}</h2><p>Low Severity</p></div>
    </div>

    <div class="methodology">
        <h3>Methodology</h3>
        <p>This report was generated using the <strong>OWASP Threat Modeling</strong> methodology
        with <strong>STRIDE</strong> threat classification. The pipeline scanned the target
        application using three tools: <strong>Bandit</strong> (static analysis),
        <strong>detect-secrets</strong> (secret detection), and
        <strong>pip-audit</strong> (dependency vulnerabilities).
        All findings are mapped back to the STRIDE threat categories identified
        in the Threat Dragon model.</p>
    </div>

    <table>
        <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Finding</th>
            <th>Tool</th>
            <th>STRIDE Category</th>
            <th>Location</th>
            <th>Description</th>
            <th>Recommendation</th>
        </tr>
        {rows}
    </table>

    <div class="footer">
        <p>Generated by DevSecOps Threat Detection Pipeline &nbsp;|&nbsp;
        OWASP Threat Modeling Cheat Sheet &nbsp;|&nbsp; {now}</p>
    </div>
</body>
</html>"""

    with open(output_file, "w") as fh:
        fh.write(html)
    print(f"[+] Report saved → {output_file}")


# ── Main Pipeline ─────────────────────────────────────────────────────────────
def run_pipeline():
    print(f"\n{'='*52}")
    print(f"  DevSecOps Threat Detection Pipeline")
    print(f"  Scanning : {TARGET_FILE}")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*52}\n")

    findings = []

    # Bandit
    bandit_data = run_bandit(TARGET_FILE)
    for issue in bandit_data.get("results", []):
        findings.append({
            "tool":        "bandit",
            "title":       f"{issue['test_id']}: {issue['test_name']}",
            "description": issue["issue_text"],
            "severity":    issue["issue_severity"],
            "line":        issue["line_number"],
            "stride":      map_to_stride(issue["test_id"]),
        })

    # detect-secrets
    secrets_data = run_detect_secrets(TARGET_FILE)
    for filename, secrets in secrets_data.get("results", {}).items():
        for secret in secrets:
            findings.append({
                "tool":        "detect-secrets",
                "title":       secret["type"],
                "description": f"Secret found at line {secret['line_number']}",
                "severity":    "HIGH",
                "line":        secret["line_number"],
                "stride":      map_to_stride(secret["type"]),
            })

    # pip-audit
    audit_data = run_pip_audit()
    for dep in audit_data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool":        "pip-audit",
                "title":       vuln["id"],
                "description": vuln["description"],
                "severity":    "HIGH",
                "line":        "N/A",
                "stride":      "Tampering",
            })

    # Terminal summary
    print(f"\n{'='*52}")
    print(f"  FINDINGS SUMMARY — {len(findings)} issues found")
    print(f"{'='*52}")
    for f in findings:
        print(f"\n  [{f['severity']}] {f['title']}")
        print(f"  Tool   : {f['tool']}")
        print(f"  STRIDE : {f['stride']}")
        print(f"  Line   : {f['line']}")
        print(f"  Detail : {f['description'][:80]}")

    # Generate HTML report
    print(f"\n{'='*52}")
    print("  Generating HTML Report...")
    print(f"{'='*52}")
    generate_report(findings, REPORT_FILE)

    # Auto-open in browser
    print("[*] Opening report in browser...")
    webbrowser.open(f"file:///{REPORT_FILE.replace(os.sep, '/')}")
    print("\n[✓] Done!\n")


if __name__ == "__main__":
    run_pipeline()
