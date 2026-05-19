# HostGuard-FIM v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/SHA--256+MD5-Dual_Hash-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Zero_Dependencies-stdlib_only-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge" />
</p>

> **Industrial-grade Host-Based File Integrity Monitor (HIDS/FIM).**  
> Cryptographically baselines files using dual SHA-256 + MD5. Detects modifications, deletions, web shell drops, and permission changes — MITRE ATT&CK annotated.

---

## 🎯 Detection Coverage

| Event | Severity | MITRE Technique |
|:---|:---:|:---|
| File Content Modified (hash mismatch) | **CRITICAL** | T1565.001 |
| Executable deleted | **CRITICAL** | T1070.004 |
| Executable file created (web shell) | **HIGH** | T1105 |
| File gained execute permission | **HIGH** | T1574 |
| File deleted | **HIGH** | T1070.004 |
| New non-executable file created | **MEDIUM** | T1105 |
| File permissions changed | **MEDIUM** | T1222 |

---

## ⚡ Quick Start

```bash
git clone https://github.com/deepmaha2006/HostGuard-FIM.git
cd HostGuard-FIM
pip install -e .

# Step 1: Baseline trusted state
hostguard baseline

# Step 2: Verify clean (no alerts expected)
hostguard check

# Step 3: Simulate a web shell drop
echo "<?php system(\$_GET['cmd']); ?>" > monitored_files/shell.php

# Step 4: Detect the intrusion
hostguard check
# → [CRITICAL] [CREATED] monitored_files/shell.php
```

---

## 📁 Project Structure

```
HostGuard-FIM/
├── hostguard/
│   ├── crypto.py     # CryptoEngine + BaselineStore (atomic JSON persistence)
│   ├── scanner.py    # FileScanner + IntegrityChecker (diff engine)
│   ├── reporter.py   # HTML forensic dashboard + JSON + alert log
│   └── cli.py        # baseline | check subcommands
├── monitored_files/   # Sample target directory
├── pyproject.toml
└── config.json
```

---

## 🔗 CI/CD Integration

```bash
# Pre-deploy gate: fail build if any file was tampered
hostguard check --fail-on-alert && echo "Deploy OK" || exit 1

# Scheduled cron (every 30 min)
*/30 * * * * /usr/local/bin/hostguard check >> /var/log/fim.log 2>&1
```

---

## 👨‍💻 Author

**Deepesh Kumar Mahawar** — B.Tech CSE (Cybersecurity), Poornima College of Engineering

[![LinkedIn](https://img.shields.io/badge/LinkedIn-deepesh--mahawar-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/deepesh-mahawar)
[![GitHub](https://img.shields.io/badge/GitHub-deepmaha2006-181717?style=flat&logo=github)](https://github.com/deepmaha2006)
