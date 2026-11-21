# Git Push Secret Protection & GitHub Repository Security 🛡️

> **Strict Zero-Secret Enforcement, Pre-Push Sanitization & Automated GitHub Cloud Security.**  
> *Prevents credential leaks, configures Secret Scanning and Push Protection, audits Dependabot CVEs, and manages CodeQL vulnerability remediation.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Zero Secrets](https://img.shields.io/badge/Security-Zero_Secret_Policy-crimson.svg)](#-the-golden-rules)
[![GitHub API: Integrated](https://img.shields.io/badge/GitHub-API_%26_CLI_Integrated-black.svg)](#-automated-github-cloud-security)
[![Scanning: Multi-Pattern](https://img.shields.io/badge/Scanner-Multi--Pattern_Regex-6366f1.svg)](#-local-secret-scanner-patterns)
[![Audit: Dependabot & CodeQL](https://img.shields.io/badge/Vulnerability-Dependabot_%26_CodeQL-success.svg)](#-vulnerability-reporting--remediation-loop)

---

## 🔒 Overview

**Git Push Secret Protection** is an end-to-end security automation skill and CLI toolkit designed to ensure:
1. **Zero Secret Leaks:** No passwords, private keys, cloud tokens, database strings, or API keys are ever committed or pushed to Git remotes.
2. **Automated Cloud Hardening:** Remote GitHub repositories are automatically configured with **Secret Scanning**, **Push Protection**, **Dependabot Security Updates**, and **CodeQL Analysis**.
3. **Continuous Vulnerability Remediation:** Fetches structured reports of CVEs and code findings directly from GitHub security APIs, enforcing a fix-and-verify gate before release.

---

## 🛑 The Golden Rules

1. **Zero Secrets in Git History:** Never commit credentials, tokens, or private keys to version control.
2. **Local Isolation via `.env`:** Always extract secrets to `.env` (strictly excluded in `.gitignore`) and supply safe dummy templates in `.env.example`.
3. **Pre-Push Sanitization:** Run `scan_secrets.py` before executing `git push`.
4. **Auto-Enable GitHub Security:** Immediately activate GitHub's security suite on every created repository.
5. **Remediation Loop:** Verify scan alerts after pushing; remediate Critical and High severity findings.

---

## 📋 The 8-Step Security Workflow

```mermaid
flowchart TD
    A["Local Code Changes"] --> B["Step 1: Run scan_secrets.py<br/>(Scans for tokens, keys, passwords)"]
    B --> C{"Secrets Detected?"}
    C -- Yes --> D["Step 2 & 3: Extract to .env<br/>Update .gitignore & untrack"]
    D --> B
    C -- No --> E["Step 4 & 5: Verify Git Diff & Push<br/>(Safe push to GitHub)"]
    E --> F["Step 6: Auto-Enable Cloud Security<br/>(Secret Scanning, Push Protection, Dependabot)"]
    F --> G["Step 7: Fetch Security Report<br/>(Check CodeQL & CVE alerts)"]
    G --> H{"Vulnerabilities Found?"}
    H -- Yes --> I["Step 8: Remediate & Re-Scan"]
    I --> E
    H -- No --> J["Verified Production Release ✅"]
```

---

## 🔍 Local Secret Scanner Patterns (`scan_secrets.py`)

The bundled scanner inspects code files against high-entropy regex patterns:

| Secret Category | Examples / Regex Patterns Detected |
| :--- | :--- |
| **Cloud Provider Keys** | Google Cloud / Gemini (`AIza...`), AWS Access Keys (`AKIA...`), Azure Storage Keys |
| **Platform & AI Tokens** | OpenAI (`sk-...`), GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`), Anthropic keys |
| **Payment Gateways** | Stripe API Keys (`sk_live_...`, `sk_test_...`), Razorpay keys |
| **Private Keys & Certs** | `-----BEGIN PRIVATE KEY-----`, RSA / OpenSSH private keys |
| **Credentials & Strings** | Hardcoded passwords (`password = "..."`), URI credentials (`postgres://user:pass@host`) |
| **Service Accounts** | Base64-encoded GCP / Firebase service account JSON files |

---

## ☁️ Automated GitHub Cloud Security (`github_security.py`)

Using the GitHub CLI (`gh api`), the toolkit automatically configures repository-level security settings:

* **Secret Scanning:** Scans committed history for known token patterns.
* **Secret Scanning Push Protection:** Server-side gate that actively rejects any future push containing detected secrets.
* **Dependabot Vulnerability Alerts & Automated Fixes:** Real-time notifications of known CVEs in package dependencies and auto-generated upgrade PRs.
* **CodeQL Code Scanning:** Static Application Security Testing (SAST) for SQL injection, XSS, and logic flaws.
* **Private Vulnerability Reporting:** Enables secure vulnerability reporting directly from security researchers.

---

## 🛠️ CLI Quick Reference

```bash
# 1. Run local secret scan on git-tracked files
python scripts/scan_secrets.py --tracked-only

# 2. Run local secret scan across the entire directory
python scripts/scan_secrets.py

# 3. Enable GitHub Secret Scanning, Push Protection, and Dependabot
python scripts/github_security.py enable

# 4. Fetch and display vulnerability report
python scripts/github_security.py report

# 5. Strict security gate (fails if Critical/High vulnerabilities exist)
python scripts/github_security.py report --strict

# 6. Complete end-to-end security audit
python scripts/github_security.py full-audit
```

---

## 📦 Directory Structure

```text
git-push-secret-protection/
├── scripts/
│   ├── github_security.py   # GitHub API security management & reporting
│   └── scan_secrets.py      # Local regex secret scanner
├── SKILL.md                 # Antigravity skill specification
├── README.md                # Project documentation
└── .gitignore               # Default security exclusion rules
```

---

## 📄 License
MIT License. Free for open source and commercial use.
