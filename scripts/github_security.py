#!/usr/bin/env python3
"""
GitHub Security Orchestrator & Vulnerability Reporter
- Automatically enables GitHub repository security features (Secret Scanning, Push Protection, Dependabot, CodeQL).
- Fetches active vulnerability and security scan alerts (Dependabot, Code Scanning, Secret Scanning).
- Formats actionable vulnerability reports to remediate issues before pushing or releasing code.
"""

import os
import sys
import json
import argparse
import subprocess
import re
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_command(cmd, capture_output=True, check=False):
    try:
        res = subprocess.run(cmd, capture_output=capture_output, text=True, check=check)
        return res.returncode, res.stdout, res.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except Exception as e:
        return 1, "", str(e)


def run_gh_api(endpoint, method="GET", fields=None):
    cmd = ["gh", "api", "--method", method, endpoint]
    if fields:
        for k, v in fields.items():
            cmd.extend(["-f", f"{k}={v}"])
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return None, stderr.strip()
    try:
        return json.loads(stdout) if stdout.strip() else {}, None
    except json.JSONDecodeError:
        return stdout.strip(), None


def get_current_repo():
    code, stdout, _ = run_command(["git", "remote", "get-url", "origin"])
    if code != 0 or not stdout.strip():
        # Fallback to gh repo view
        code2, stdout2, _ = run_command(["gh", "repo", "view", "--json", "nameWithOwner"])
        if code2 == 0 and stdout2.strip():
            try:
                data = json.loads(stdout2)
                return data.get("nameWithOwner")
            except Exception:
                pass
        return None
    url = stdout.strip()
    # Match git@github.com:owner/repo.git or https://github.com/owner/repo.git
    m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+?)(?:\.git)?$", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return None


def enable_all_security(repo_nwo):
    print(f"\n=======================================================")
    print(f"[*] ENABLING GITHUB SECURITY SUITE: {repo_nwo}")
    print("=======================================================")

    results = []

    # 1. Dependabot vulnerability alerts
    print("[*] 1/5 Enabling Dependabot Vulnerability Alerts...")
    _, err = run_gh_api(f"/repos/{repo_nwo}/vulnerability-alerts", method="PUT")
    if not err:
        print("    [+] Dependabot alerts enabled successfully.")
        results.append(("Dependabot Alerts", "ENABLED"))
    else:
        print(f"    [-] Dependabot alerts: {err}")
        results.append(("Dependabot Alerts", f"NOTE: {err}"))

    # 2. Automated security fixes
    print("[*] 2/5 Enabling Dependabot Automated Security Fixes...")
    _, err = run_gh_api(f"/repos/{repo_nwo}/automated-security-fixes", method="PUT")
    if not err:
        print("    [+] Dependabot automated security fixes enabled.")
        results.append(("Dependabot Auto-Fixes", "ENABLED"))
    else:
        print(f"    [-] Dependabot fixes: {err}")
        results.append(("Dependabot Auto-Fixes", f"NOTE: {err}"))

    # 3. Secret scanning & Push Protection
    print("[*] 3/5 Enabling Secret Scanning & Push Protection...")
    _, err = run_gh_api(
        f"/repos/{repo_nwo}",
        method="PATCH",
        fields={
            "security_and_analysis[secret_scanning][status]": "enabled",
            "security_and_analysis[secret_scanning_push_protection][status]": "enabled"
        }
    )
    if not err:
        print("    [+] Secret Scanning & Push Protection enabled.")
        results.append(("Secret Scanning & Push Protection", "ENABLED"))
    else:
        print(f"    [-] Secret Scanning: {err}")
        results.append(("Secret Scanning & Push Protection", f"NOTE: {err}"))

    # 4. Private Vulnerability Reporting
    print("[*] 4/5 Enabling Private Vulnerability Reporting...")
    _, err = run_gh_api(
        f"/repos/{repo_nwo}",
        method="PATCH",
        fields={"private_vulnerability_reporting": "true"}
    )
    if not err:
        print("    [+] Private Vulnerability Reporting enabled.")
        results.append(("Private Vulnerability Reporting", "ENABLED"))
    else:
        print(f"    [-] Private Vulnerability Reporting: {err}")
        results.append(("Private Vulnerability Reporting", f"NOTE: {err}"))

    # 5. CodeQL Code Scanning Default Setup
    print("[*] 5/5 Configuring CodeQL Code Scanning (Default Setup)...")
    _, err = run_gh_api(
        f"/repos/{repo_nwo}/code-scanning/default-setup",
        method="PATCH",
        fields={"state": "configured"}
    )
    if not err:
        print("    [+] CodeQL Code Scanning configured.")
        results.append(("CodeQL Code Scanning", "CONFIGURED"))
    else:
        print(f"    [-] CodeQL Code Scanning: {err}")
        results.append(("CodeQL Code Scanning", f"NOTE: {err}"))

    print("\n[+] Security Configuration Completed.")
    return results


def fetch_security_alerts(repo_nwo):
    print(f"\n=======================================================")
    print(f"[*] FETCHING REPOSITORY SECURITY ALERTS: {repo_nwo}")
    print("=======================================================")

    report = {
        "dependabot": [],
        "code_scanning": [],
        "secret_scanning": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }

    # Fetch Dependabot Alerts
    data, err = run_gh_api(f"/repos/{repo_nwo}/dependabot/alerts?state=open")
    if isinstance(data, list):
        for alert in data:
            adv = alert.get("security_advisory", {})
            vuln = alert.get("security_vulnerability", {})
            pkg = vuln.get("package", {}).get("name", "unknown")
            severity = adv.get("severity", "unknown").lower()
            patched = vuln.get("first_patched_version", {}).get("identifier", "No fix available")

            if severity in report["summary"]:
                report["summary"][severity] += 1
            else:
                report["summary"]["medium"] += 1

            report["dependabot"].append({
                "number": alert.get("number"),
                "package": pkg,
                "severity": severity.upper(),
                "summary": adv.get("summary", ""),
                "patched_version": patched,
                "url": alert.get("html_url", "")
            })
    elif err:
        print(f"[-] Note for Dependabot alerts: {err}")

    # Fetch Code Scanning Alerts
    data, err = run_gh_api(f"/repos/{repo_nwo}/code-scanning/alerts?state=open")
    if isinstance(data, list):
        for alert in data:
            rule = alert.get("rule", {})
            loc = alert.get("most_recent_instance", {}).get("location", {})
            path = loc.get("path", "unknown")
            start_line = loc.get("start_line", 0)
            severity = rule.get("security_severity_level", rule.get("severity", "medium")).lower()

            if severity in report["summary"]:
                report["summary"][severity] += 1
            else:
                report["summary"]["medium"] += 1

            report["code_scanning"].append({
                "number": alert.get("number"),
                "rule": rule.get("id"),
                "severity": severity.upper(),
                "description": rule.get("description", ""),
                "location": f"{path}:{start_line}",
                "url": alert.get("html_url", "")
            })
    elif err:
        print(f"[-] Note for Code Scanning alerts: {err}")

    # Fetch Secret Scanning Alerts
    data, err = run_gh_api(f"/repos/{repo_nwo}/secret-scanning/alerts?state=open")
    if isinstance(data, list):
        for alert in data:
            report["summary"]["critical"] += 1
            report["secret_scanning"].append({
                "number": alert.get("number"),
                "secret_type": alert.get("secret_type_display_name", alert.get("secret_type", "Secret")),
                "severity": "CRITICAL",
                "created_at": alert.get("created_at"),
                "url": alert.get("html_url", "")
            })
    elif err:
        print(f"[-] Note for Secret Scanning alerts: {err}")

    # Print Summary Report
    s = report["summary"]
    total = sum(s.values())
    print("\n-------------------------------------------------------")
    print(f"📊 SECURITY SCAN AUDIT SUMMARY: {total} Open Finding(s)")
    print(f"   🔴 Critical: {s['critical']} | 🟠 High: {s['high']} | 🟡 Medium: {s['medium']} | ⚪ Low: {s['low']}")
    print("-------------------------------------------------------")

    if report["secret_scanning"]:
        print("\n🚨 UNRESOLVED SECRET SCANNING ALERTS (CRITICAL):")
        for item in report["secret_scanning"]:
            print(f"  - [Alert #{item['number']}] {item['secret_type']} -> {item['url']}")

    if report["code_scanning"]:
        print("\n🔍 CODE SCANNING / CODEQL FINDINGS:")
        for item in report["code_scanning"]:
            print(f"  - [{item['severity']}] {item['location']}: {item['description']} ({item['rule']})")
            print(f"    Link: {item['url']}")

    if report["dependabot"]:
        print("\n📦 DEPENDABOT VULNERABILITY ALERTS:")
        for item in report["dependabot"]:
            print(f"  - [{item['severity']}] Package: {item['package']} | Patched: {item['patched_version']}")
            print(f"    Summary: {item['summary']}")
            print(f"    Link: {item['url']}")

    if total == 0:
        print("\n🎉 EXCELLENT: Repository has 0 open security alerts or vulnerabilities!")

    return report


def main():
    parser = argparse.ArgumentParser(description="Automate GitHub repository security and report vulnerability scans.")
    parser.add_argument("action", choices=["enable", "report", "full-audit"], help="Action to perform")
    parser.add_argument("--repo", default=None, help="Target GitHub repository (e.g. owner/repo). Inferred from git remote if omitted.")
    parser.add_argument("--strict", action="store_true", help="Exit with error code 1 if Critical or High vulnerabilities are found.")
    args = parser.parse_args()

    repo = args.repo or get_current_repo()
    if not repo:
        print("[!] Error: Could not determine GitHub repository. Please specify --repo owner/repo or run from a git repository with an origin remote.")
        sys.exit(1)

    if args.action == "enable":
        enable_all_security(repo)
    elif args.action == "report":
        report = fetch_security_alerts(repo)
        if args.strict and (report["summary"]["critical"] > 0 or report["summary"]["high"] > 0):
            print("\n[!] STRICT MODE: Blocking further actions due to Critical/High security alerts.")
            sys.exit(1)
    elif args.action == "full-audit":
        enable_all_security(repo)
        report = fetch_security_alerts(repo)
        if args.strict and (report["summary"]["critical"] > 0 or report["summary"]["high"] > 0):
            print("\n[!] STRICT MODE: Blocking push/merge due to unresolved vulnerabilities.")
            sys.exit(1)


if __name__ == "__main__":
    main()
