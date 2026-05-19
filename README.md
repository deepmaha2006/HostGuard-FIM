# HostGuard-FIM v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/SHA--256+MD5-Dual_Hash-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Zero_Dependencies-stdlib_only-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-cross--platform-blue?style=for-the-badge" />
</p>

> **Industrial-grade Host-Based File Integrity Monitor (HIDS/FIM).**
> Cryptographically baselines files using dual SHA-256 + MD5. Detects modifications, deletions, web shell drops,
> and permission changes -- all MITRE ATT&CK annotated.

---

## Features

| Event | Severity | MITRE Technique |
|:---|:---:|:---|
| File Content Modified (hash mismatch) | **CRITICAL** | T1565.001 |
| Executable file deleted | **CRITICAL** | T1070.004 |
| Executable file created (web shell drop) | **HIGH** | T1105 |
| File gained execute permission | **HIGH** | T1574 |
| File deleted | **HIGH** | T1070.004 |
| New non-executable file created | **MEDIUM** | T1105 |
| File permissions changed | **MEDIUM** | T1222 |

---

## Quick Start

```bash
git clone https://github.com/deepmaha2006/HostGuard-FIM.git
cd HostGuard-FIM
pip install -e .

# Step 1: Baseline trusted state
hostguard baseline

# Step 2: Verify clean system (0 alerts expected)
hostguard check

# Step 3: Simulate a file tampering
echo "attacker_content" > monitored_files/new_upload.php

# Step 4: Detect the intrusion
hostguard check
# -> [CRITICAL] [MODIFIED] or [HIGH] [CREATED] alert fires
```

---

## Advanced Usage

```bash
# Monitor custom directories
hostguard baseline --paths /var/www /etc/nginx /opt/app

# Generate reports to custom dir
hostguard check --output-dir /var/log/fim-reports

# CI/CD gate -- fail build if tampering detected
hostguard check --fail-on-alert && echo "Deploy OK" || exit 1

# Scheduled cron (every 30 min)
*/30 * * * * /usr/local/bin/hostguard check >> /var/log/fim.log 2>&1
```

---

## Project Structure

```
HostGuard-FIM/
|-- hostguard/
|   |-- __init__.py    # Package metadata
|   |-- crypto.py      # CryptoEngine (SHA-256+MD5) + BaselineStore (atomic JSON)
|   |-- scanner.py     # FileScanner + IntegrityChecker (diff engine)
|   |-- reporter.py    # HTML forensic dashboard + JSON + alert log
|   `-- cli.py         # baseline | check subcommands
|-- monitored_files/   # Sample target directory
|-- pyproject.toml
`-- config.json
```

---

## Reports Generated

| Format | Contents |
|:---|:---|
| `hostguard_TIMESTAMP.html` | Interactive dark forensic dashboard with severity breakdown |
| `hostguard_TIMESTAMP.json` | Structured alert data for SIEM/SOAR ingestion |
| `hostguard_TIMESTAMP.log` | Plain-text incident log for archiving |

---

## Author

**Deepesh Kumar Mahawar** -- B.Tech CSE (Cybersecurity), Poornima College of Engineering

[![LinkedIn](https://img.shields.io/badge/LinkedIn-deepesh--mahawar-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/deepesh-mahawar)
[![GitHub](https://img.shields.io/badge/GitHub-deepmaha2006-181717?style=flat&logo=github)](https://github.com/deepmaha2006)
