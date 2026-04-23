import subprocess
import json
<<<<<<< HEAD
import os
=======
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
from datetime import datetime

def run_bandit(target_file):
    print("\n[*] Running Bandit (Static Analysis)...")
    result = subprocess.run(
        ["bandit", "-f", "json", target_file],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def run_detect_secrets(target_file):
    print("[*] Running detect-secrets (Secret Scanner)...")
    result = subprocess.run(
        ["detect-secrets", "scan", target_file],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def run_pip_audit():
    print("[*] Running pip-audit (Dependency Check)...")
    result = subprocess.run(
        ["pip-audit", "--format", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def map_to_stride(issue_type):
    stride_map = {
        "hardcoded_password_string": "Information Disclosure",
        "hardcoded_sql_expressions": "Tampering",
        "Secret Keyword":            "Information Disclosure",
        "CVE":                       "Tampering",
        "B105":                      "Information Disclosure",
        "B608":                      "Tampering",
        "B106":                      "Information Disclosure",
        "B107":                      "Information Disclosure"
    }
  
    for key in stride_map:
        if key.lower() in issue_type.lower():
            return stride_map[key]
    return "Unknown"

def run_pipeline(target_file):
    print(f"\n{'='*50}")
    print(f"  DevSecOps Threat Detection Pipeline")
    print(f"  Scanning: {target_file}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    findings = []

    # Bandit scan
    bandit_results = run_bandit(target_file)
    for issue in bandit_results.get("results", []):
        findings.append({
            "tool": "bandit",
            "title": issue["test_id"],
            "description": issue["issue_text"],
            "severity": issue["issue_severity"],
            "line": issue["line_number"],
            "stride": map_to_stride(issue["test_id"])
        })

    # detect-secrets scan
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

    # pip-audit scan
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

    # Print summary
    print(f"\n{'='*50}")
    print(f"  FINDINGS SUMMARY — {len(findings)} issues found")
    print(f"{'='*50}")
    for f in findings:
        print(f"\n  [{f['severity']}] {f['title']}")
        print(f"  Tool     : {f['tool']}")
        print(f"  STRIDE   : {f['stride']}")
        print(f"  Line     : {f['line']}")
        print(f"  Detail   : {f['description'][:80]}")

    return findings

if __name__ == "__main__":
<<<<<<< HEAD
    # Use path relative to this script's location so it works from any directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, "code vulnerable_app.py")
    run_pipeline(target)
=======
    run_pipeline("code vulnerable_app.py")
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
