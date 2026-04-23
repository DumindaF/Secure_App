import subprocess
import json
import os
from datetime import datetime

def run_bandit(target_file):
    result = subprocess.run(
        ["bandit", "-f", "json", target_file],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def run_detect_secrets(target_file):
    result = subprocess.run(
        ["detect-secrets", "scan", target_file],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def run_pip_audit():
    result = subprocess.run(
        ["pip-audit", "--format", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def map_to_stride(issue_type):
    stride_map = {
        "B105": "Information Disclosure",
        "B608": "Tampering",
        "B106": "Information Disclosure",
        "B107": "Information Disclosure",
        "Secret Keyword": "Information Disclosure",
        "CVE": "Tampering"
    }
    for key in stride_map:
        if key.lower() in issue_type.lower():
            return stride_map[key]
    return "Unknown"

def severity_color(severity):
    colors = {
        "HIGH":     "#e74c3c",
        "MEDIUM":   "#e67e22",
        "LOW":      "#f1c40f",
        "CRITICAL": "#8e44ad"
    }
    return colors.get(severity.upper(), "#95a5a6")

def generate_report(findings, output_file="threat_report.html"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high   = sum(1 for f in findings if f["severity"].upper() == "HIGH")
    medium = sum(1 for f in findings if f["severity"].upper() == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"].upper() == "LOW")

    rows = ""
    for i, f in enumerate(findings, 1):
        color = severity_color(f["severity"])
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
        .total {{ border-top: 4px solid #2c3e50; }}
        .high {{ border-top: 4px solid #e74c3c; }}
        .medium {{ border-top: 4px solid #e67e22; }}
        .low {{ border-top: 4px solid #f1c40f; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; font-size: 14px; }}
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
        <div class="card total">
            <h2>{len(findings)}</h2>
            <p>Total Findings</p>
        </div>
        <div class="card high">
            <h2 style="color:#e74c3c">{high}</h2>
            <p>High Severity</p>
        </div>
        <div class="card medium">
            <h2 style="color:#e67e22">{medium}</h2>
            <p>Medium Severity</p>
        </div>
        <div class="card low">
            <h2 style="color:#f1c40f">{low}</h2>
            <p>Low Severity</p>
        </div>
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
        </tr>
        {rows}
    </table>

    <div class="footer">
        <p>Generated by DevSecOps Threat Detection Pipeline &nbsp;|&nbsp;
        OWASP Threat Modeling Cheat Sheet &nbsp;|&nbsp; {now}</p>
    </div>
</body>
</html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"\n[+] Report saved to {output_file}")

def run_pipeline(target_file):
    print(f"\n{'='*50}")
    print(f"  Generating Threat Report...")
    print(f"{'='*50}")

    findings = []

    bandit_results = run_bandit(target_file)
    for issue in bandit_results.get("results", []):
        findings.append({
            "tool": "bandit",
            "title": issue["test_id"] + ": " + issue["test_name"],
            "description": issue["issue_text"],
            "severity": issue["issue_severity"],
            "line": issue["line_number"],
            "stride": map_to_stride(issue["test_id"])
        })

    secrets_results = run_detect_secrets(target_file)
    for filename, secrets in secrets_results.get("results", {}).items():
        for secret in secrets:
            findings.append({
                "tool": "detect-secrets",
                "title": secret["type"],
                "description": f"Secret found at line {secret['line_number']}",
                "severity": "HIGH",
                "line": secret["line_number"],
                "stride": map_to_stride(secret["type"])
            })

    audit_results = run_pip_audit()
    for dep in audit_results.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool": "pip-audit",
                "title": vuln["id"],
                "description": vuln["description"],
                "severity": "HIGH",
                "line": "N/A",
                "stride": "Tampering"
            })

    generate_report(findings)

if __name__ == "__main__":
    # Use path relative to this script's location so it works from any directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, "..", "pipeline", "code vulnerable_app.py")
    run_pipeline(target)