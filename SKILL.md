---
name: git-push-secret-protection
description: >-
  Strictly enforces zero-secret security and automates GitHub repository security
  before and after pushing code. Scans codebase for passwords, API keys, credentials,
  and sensitive configs, migrates them to .env, and ensures .gitignore compliance.
  Automatically enables repository security features (Secret Scanning, Push Protection,
  Dependabot, CodeQL) on GitHub, fetches vulnerability scan reports, and enforces a
  remediation loop before final code releases.
---

# Git Push Secret Protection & GitHub Repository Security Skill

This skill strictly enforces that:
1. **NO secrets, passwords, credentials, or API keys** are ever committed or pushed to any repository.
2. **All GitHub repository security features** are turned on automatically when creating or updating a repository.
3. **Automated vulnerability scans** (Dependabot, CodeQL, Secret Scanning) are fetched, analyzed, and reported back so issues can be fixed and re-scanned.

Whenever a commit or `git push` is planned or requested, follow this mandatory 8-step workflow.

---

## 🛑 Golden Rules: Security at Source & in the Cloud

1. **Zero Secrets in Git**: Never commit API keys, tokens, passwords, or private keys to version control.
2. **Local Isolation via `.env`**: Always extract secrets to `.env` (strictly ignored by `.gitignore`) and provide dummy keys in `.env.example`.
3. **Pre-Push Sanitization**: Always run `scan_secrets.py` before executing `git push`.
4. **Auto-Enable GitHub Security**: Automatically enable Secret Scanning, Push Protection, Dependabot alerts, Dependabot security updates, and CodeQL on every remote repository.
5. **Analyze & Remediate Vulnerabilities**: Fetch scan alerts after pushing or before releasing; flag Critical/High issues, fix them, and re-scan.

---

## 📋 Complete Step-by-Step Execution Workflow

### Step 1: Pre-Scan the Codebase for Secrets

Run the bundled secret scanner locally:

```bash
# Scan only git-tracked files
python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/scan_secrets.py --tracked-only

# Or full directory scan
python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/scan_secrets.py
```

Scans for:
- API Keys (`AIza...`, `sk-...`, `ghp_...`, AWS `AKIA...`, Stripe `sk_...`)
- Passwords & User Credentials (`password = "..."`, `user:pass@host`)
- Private keys (`-----BEGIN PRIVATE KEY-----`)
- Base64-encoded Service Accounts (`ewogICJ...`)
- Webhook URLs and Bearer Tokens

---

### Step 2: Extract Secrets to `.env` & Update Code

If any sensitive values are found:
1. **Move to `.env`**: Store real secret values in the root `.env`.
2. **Update Code**: Replace hardcoded values with `os.getenv()` (Python), `process.env` (JS/TS), or `String.fromEnvironment()` (Dart).
3. **Update `.env.example`**: List keys with dummy values (e.g. `GEMINI_API_KEY=""`).

---

### Step 3: Verify `.gitignore` Exclusions

Confirm `.env` and credential files are never committed:
```bash
git ls-files --error-unmatch .env
```
If `.env` is tracked, untrack it immediately:
```bash
git rm --cached .env
```

Ensure `.gitignore` contains:
```gitignore
.env
.env.*
*.env
!*.example
!*.example.*
*service-account*.json
*.pem
*.key
```

---

### Step 4: Verify Git Diff Before Staging / Committing

Audit exact staged changes to ensure no sensitive files or lines slipped in:
```bash
git status
git diff --staged
```

---

### Step 5: Safe Git Push

Once all secret scans pass with 0 warnings:
```bash
git add <only-sanitized-files>
git commit -m "feat/fix: descriptive commit message without secrets"
git push origin <branch>
```

---

### Step 6: Automatically Enable GitHub Repository Security Features

When creating a new repository or pushing to an existing repository, immediately activate the full GitHub security suite:

```bash
python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py enable
```

This command uses the GitHub CLI (`gh api`) to automatically enable:
* **Secret Scanning**: Scans committed history for known token patterns.
* **Secret Scanning Push Protection**: Server-side gate that actively rejects any future push containing detected secrets.
* **Dependabot Vulnerability Alerts**: Real-time notifications of known CVEs in package dependencies.
* **Dependabot Automated Security Fixes**: Automatically opens pull requests to patch vulnerable dependencies.
* **CodeQL Code Scanning**: Sets up AST-level static security analysis for code-level vulnerabilities.
* **Private Vulnerability Reporting**: Enables secure vulnerability reporting directly from researchers.

---

### Step 7: Automated Vulnerability Scan & Alert Reporting

Retrieve and inspect vulnerability scan results directly:

```bash
python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py report
```

Add `--strict` to fail with exit code 1 if any Critical or High severity vulnerabilities exist:
```bash
python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py report --strict
```

The script outputs a structured markdown/console summary:
* 📊 **Severity Totals**: Breakdown of Critical, High, Medium, and Low vulnerabilities.
* 🚨 **Secret Scanning Alerts**: Any active secrets flagged by GitHub.
* 🔍 **CodeQL Code Findings**: File path, line number, rule ID, and vulnerability description.
* 📦 **Dependabot CVEs**: Affected package, patched version identifier, and advisory link.

---

### Step 8: Remediation & Re-Scan Loop

1. **Review Report**: Identify any Critical or High severity findings.
2. **Remediate**:
   - For **Dependabot**: Update the package version in `package.json`, `requirements.txt`, `pyproject.toml`, or `pubspec.yaml` to the recommended patched version.
   - For **CodeQL**: Patch the flagged code line (e.g. SQL injection, path traversal, insecure deserialization).
   - For **Secret Scanning**: Revoke the leaked credential and remove it from commit history.
3. **Re-Scan & Push**:
   - Re-run local check: `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/scan_secrets.py`
   - Commit fixes: `git commit -am "security: remediate CVEs and code scanning alerts"`
   - Push to remote: `git push origin <branch>`
   - Re-verify alerts: `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py report`

---

## 🛠️ Quick Reference Commands

| Action | Command |
| :--- | :--- |
| **Local Secret Scan** | `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/scan_secrets.py --tracked-only` |
| **Verify .env is Untracked** | `git rm --cached .env` |
| **Enable GitHub Security Features** | `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py enable` |
| **Fetch & Report Vulnerabilities** | `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py report` |
| **Strict Security Gate** | `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py report --strict` |
| **Full Security Setup & Audit** | `python C:/Users/harsh/.gemini/config/skills/git-push-secret-protection/scripts/github_security.py full-audit` |
