# Linux Vulnerability Scanner and Security Assessment Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![Platform Support](https://img.shields.io/badge/platform-Rocky%20Linux%209%20%7C%20RHEL%208%2F9%20%7C%20Alma%20%7C%20Ubuntu%20%7C%20Debian-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-purple.svg)]()
[![Read--Only Security](https://img.shields.io/badge/mode-read--only%20audit-brightgreen.svg)]()

A high-fidelity, practical **Linux Vulnerability Scanner and Security Assessment Tool** designed for Linux servers in production environments, particularly AWS EC2 instances and on-premise infrastructure running **Rocky Linux 9.6 (Blue Onyx), Red Hat Enterprise Linux (RHEL 8/9), AlmaLinux, CentOS Stream, Ubuntu LTS, Debian stable, and Amazon Linux**.

Unlike conventional vulnerability scanners that generate high volumes of false positives by merely pattern-matching package strings against NVD version ranges, this tool implements an **Intelligent Applicability Engine**. It assesses **RPM/Debian EVR (Epoch-Version-Release)**, vendor backported security patches (RHSA/RLSA/USN), **CPU hardware instruction-set extensions (such as AVX-512 VBMI)**, **JVM runtime flags**, **systemd service states**, and **active configuration directives (e.g. NGINX HTTP/2 listener states)** before determining applicability.

---

## Key Features

1. **Strict Read-Only & Non-Destructive**: Never installs packages, alters configs, restarts services, or executes exploit payloads. Enforces least-privilege auditing.
2. **True Vendor Backport Analysis (RPM `rpmvercmp` & Debian `debvercmp`)**: Understands vendor errata versioning (e.g., `1.20.1-14.el9_2.3` fixes CVE-2023-44487 while upstream version remains `1.20.1`).
3. **Deep Prerequisite & Hardware Applicability Evaluation**:
   - Hardware instructions: Inspects `/proc/cpuinfo` flags (e.g. `avx512_vbmi`, `aes`, `sse4_2`).
   - Runtime options: Evaluates active JVM flags (e.g. `-XX:-UseBase64Intrinsics`, `-XX:UseAVX`).
   - Configuration directives: Audits NGINX (`nginx -T`), Apache HTTP Server (`httpd -M`), TLS configurations, and HTTP/2 directives.
4. **Authoritative 6-State Vulnerability Classification**:
   - `Affected`: Confirmed vulnerable component + all prerequisite runtime and hardware conditions met.
   - `Potentially affected`: Unpatched binary installed, but daemon is currently stopped/inactive.
   - `Not affected`: Component not installed, or hardware prerequisites (e.g. AVX-512 VBMI) are provably absent.
   - `Mitigated`: Unpatched binary installed, but mitigating configuration (e.g. HTTP/2 disabled, intrinsic disabled) is active.
   - `Fixed`: Authoritative vendor backported security patch or updated release is verified installed.
   - `Unable to determine`: Insufficient evidence or unparsable binary signature.
5. **Multi-Factor Risk Prioritization**: Combines CVSS v3.1, FIRST EPSS (Exploit Prediction Scoring System), CISA KEV (Known Exploited Vulnerabilities catalog), and exposure conditions to rank findings into an actionable remediation backlog.
6. **Built-in Secret Sanitization**: Redacts private keys, tokens, passwords, and AWS credentials from evidence strings before storage or rendering.
7. **Multi-Format Professional Reporting**:
   - **Interactive HTML**: Responsive dashboard with client-side filtering, search, and collapsible evidence drawers (zero external CDN dependencies).
   - **Standalone PDF**: Clean, paginated executive summary, metrics tables, and evidence appendix generated via pure Python.
   - **Structured JSON**: Machine-readable output for SIEM, DefectDojo, Jira, and CI/CD pipelines.
   - **Executive CSV**: Formatted spreadsheet summary for auditors and management.
8. **Dual UI Modes**:
   - Built-in zero-dependency HTTP Web Dashboard (`vulnscan serve --port 8080`).
   - Optional Streamlit Console (`streamlit run vulnscan/ui/streamlit_app.py`).

---

## Architecture Overview

```
                                    +-----------------------------------------------+
                                    |       Target Linux Host (Local or Remote)     |
                                    |  - /etc/os-release, uname, DMI (AWS EC2)       |
                                    |  - rpm -qa / dpkg-query                       |
                                    |  - /proc/cpuinfo (AVX-512, VBMI, AES)         |
                                    |  - systemctl list-units, ss -tulpen           |
                                    |  - nginx -T, httpd -M, JVM flags              |
                                    +-----------------------+-----------------------+
                                                            |
                                               [InventoryCollector]
                                                            v
                                            +-------------------------------+
                                            |       SystemInventory         |
                                            +---------------+---------------+
                                                            |
+-----------------------------------------------------------+-----------------------------------------------------------+
|                                                           |                                                           |
v                                                           v                                                           v
[Authoritative Advisory Sources]               [Rule-Based Applicability Engine]                         [Sanitizer]
- Red Hat / Rocky Errata (RHSA/RLSA)           - RPM EVR / Debian version matcher                         - Redacts Private Keys
- Ubuntu USN / Debian Security Tracker         - Vendor Backported patch evaluator                        - Redacts Passwords & Tokens
- CISA Known Exploited (KEV)                   - Hardware instruction validator (AVX-512 VBMI)            - Redacts AWS Secrets
- FIRST EPSS Scores                            - Active config validator (HTTP/2, JVM flags)
- Offline Cache & Seed DB                      - Running daemon status evaluator
                                                            |
                                                            v
                                            +-------------------------------+
                                            |     Multi-Factor Prioritizer  |
                                            | (CVSS + EPSS + KEV + Exposure)|
                                            +---------------+---------------+
                                                            |
                                                            v
                                            +-------------------------------+
                                            |          ScanReport           |
                                            +---------------+---------------+
                                                            |
                 +--------------------------+---------------+--------------------------+
                 v                          v               v                          v
          [HtmlReporter]              [PdfReporter]   [JsonReporter]             [CsvReporter]
        (Interactive Dark UI)       (Paginated PDF)    (SIEM / JSON)             (Spreadsheet)
```

---

## Directory Structure

```
linux-vuln-scanner/
├── setup.py                          # Packaging and CLI console script definition
├── requirements.txt                  # Dependency specifications (Core has 0 dependencies!)
├── config.example.yaml               # Example scanner configuration
├── README.md                         # Architecture, installation, and operation guide
├── vulnscan/
│   ├── __init__.py                   # Package versioning
│   ├── cli.py                        # Complete CLI subcommands (scan-local, scan-remote, serve)
│   ├── core/
│   │   ├── models.py                 # Strongly-typed dataclasses and enums
│   │   ├── evr.py                    # RPM rpmvercmp and Debian version comparison
│   │   ├── sanitizer.py              # Secret, private key, and credential redactor
│   │   ├── rules.py                  # Intelligent Applicability Evaluation Engine
│   │   ├── risk.py                   # Multi-Factor Risk Prioritizer (CVSS, EPSS, KEV)
│   │   └── engine.py                 # Pipeline Orchestrator
│   ├── inventory/
│   │   ├── collector.py              # Master Inventory Collector and Reference Profiles
│   │   ├── os_detector.py            # /etc/os-release, uname, AWS EC2 DMI identification
│   │   ├── cpu_analyzer.py           # /proc/cpuinfo AVX-512, VBMI, and feature analysis
│   │   ├── package_collector.py      # RPM / DPKG collection and DNF updateinfo queries
│   │   ├── software_detector.py      # Standalone/bundled runtime detector (Java, Node, NGINX)
│   │   ├── service_collector.py      # systemd units and listening sockets (ss/netstat)
│   │   └── config_analyzer.py        # NGINX (nginx -T), Apache, and JVM runtime flag audit
│   ├── advisories/
│   │   ├── base.py                   # VulnerabilitySource abstract interface
│   │   ├── cache.py                  # Persistent JSON cache with TTL & staleness checks
│   │   ├── rhel_rocky.py             # Rocky Linux & Red Hat advisory source
│   │   ├── ubuntu_debian.py          # Ubuntu Security Notices & Debian Tracker source
│   │   ├── cisa_kev.py               # CISA Known Exploited Vulnerabilities catalog
│   │   ├── epss.py                   # FIRST EPSS probability and percentile provider
│   │   └── manager.py                # Multi-source intelligence coordinator
│   ├── reporting/
│   │   ├── html_reporter.py          # Self-contained, responsive, dark-theme HTML report
│   │   ├── pdf_reporter.py           # Pure-Python zero-dependency PDF 1.4 report generator
│   │   └── json_reporter.py          # Structured JSON and CSV export generators
│   ├── remote/
│   │   └── ssh_runner.py             # Read-only SSH command executor with safety guards
│   └── ui/
│       ├── web_server.py             # Built-in zero-dependency HTTP Web Dashboard
│       └── streamlit_app.py          # Streamlit UI dashboard
├── data/
│   └── sample_advisories.json        # Authoritative offline seed database
├── samples/                          # Sample generated reports
│   ├── sample_report.html
│   ├── sample_report.pdf
│   ├── sample_report.json
│   └── sample_report.csv
└── tests/                            # Comprehensive Automated Test Suite (25 Tests)
    ├── test_evr.py                   # EVR algorithm & version parsing tests
    ├── test_os_detector.py           # Rocky 9.6, Ubuntu, and CPU flag tests
    ├── test_config_analyzer.py       # NGINX HTTP/2, JVM flags, and Sanitizer tests
    ├── test_scenarios.py             # Real-world scenarios (CVE-2026-114938, CVE-2026-123633)
    └── test_reporters.py             # HTML, PDF, JSON, and CSV output validation
```

---

## Installation

### Prerequisites
- Python 3.8 or higher.
- Standard Linux utilities (`rpm`, `dpkg`, `uname`, `systemctl`, `ss`, or `cat /proc/...`).

### Standalone / Zero-Dependency Setup
The core scanning engine, inventory collector, EVR comparison, applicability engine, CLI, zero-dependency Web Dashboard, HTML reporting, JSON reporting, CSV reporting, and PDF reporting require **ZERO external pip packages**. You can run it immediately on any Linux server:

```bash
git clone https://github.com/hex2607/linux-vuln-scanner.git
cd linux-vuln-scanner
export PYTHONPATH=.
python3 -m vulnscan.cli --help
```

### Development or Full UI Installation
To enable the optional Streamlit UI and install console shortcuts:

```bash
pip install -e .
pip install streamlit paramiko
```

---

## Quick Start & CLI Usage

### 1. Run Assessment on Current Local Linux Server
Runs non-destructive inventory collection, audits packages and configs, evaluates advisories, and generates all report formats:

```bash
vulnscan scan-local --output-dir ./reports --format html,pdf,json,csv
```

### 2. Run Rocky Linux 9.6 Reference Assessment
Evaluates the reference Rocky Linux 9.6 environment with pre-seeded advisories (e.g. OpenJDK AVX-512 and NGINX HTTP/2 CVEs):

```bash
vulnscan scan-local --profile rocky9 --output-dir ./reports
```

You can test specific scenario variations:
- `--scenario default`: Unpatched NGINX with HTTP/2 enabled + OpenJDK with AVX-512 VBMI (`Affected`).
- `--scenario mitigated_nginx`: HTTP/2 disabled in NGINX config (`Mitigated`).
- `--scenario mitigated_openjdk`: JVM flag `-XX:-UseBase64Intrinsics` enabled (`Mitigated`).
- `--scenario non_avx512`: CPU lacks AVX-512 VBMI instruction set (`Not affected`).
- `--scenario patched`: Vendor backported packages installed (`Fixed`).

### 3. Target Specific CVE(s) (`--cve` Flag)
Assess solely for one or more specific CVE IDs during incident response, targeted re-audits, or change validation:

```bash
# Scan locally for a single specific CVE
vulnscan scan-local --cve CVE-2021-3156 --profile rocky9

# Scan for multiple comma-separated CVEs
vulnscan scan-local --cve CVE-2021-3156,CVE-2023-44487

# Works with launcher script
bash run.sh scan-local --profile rocky9 --cve CVE-2021-3156

# Target specific CVEs on a remote server over SSH
vulnscan scan-remote --host 10.0.1.50 --user ec2-user --key-file ~/.ssh/id_rsa --cve CVE-2021-3156
```

### 4. Remote Scan via SSH (Read-Only)
Assesses a remote Linux server using SSH keys with strict read-only execution guardrails:

```bash
vulnscan scan-remote \
  --host 10.0.1.50 \
  --user ec2-user \
  --key-file ~/.ssh/id_rsa \
  --output-dir ./reports
```

*Note: The scanner checks every command against a safety blacklist, prohibiting `rm`, `dnf install`, `systemctl restart`, `reboot`, etc.*

### 5. Multi-Server Fleet Assessment (`scan-fleet`)
Assesses an entire fleet of Linux servers concurrently from an inventory file (`.json`, `.yaml`, or `.csv`) and generates consolidated posture metrics, compliance scores, and a fleet-wide CVE exposure heat-matrix:

```bash
# Scan fleet concurrently across servers defined in inventory
vulnscan scan-fleet --fleet-file data/sample_fleet.json --concurrency 5 --output-dir ./reports

# Consolidated reports generated:
# - fleet-report-<timestamp>.json
# - fleet-report-<timestamp>.csv
# - fleet-report-<timestamp>.html (interactive fleet dashboard)
```

### 6. Historical Scan Comparison & Diffing (`diff`)
Compares two scan JSON reports across time (e.g. before and after patching) to identify newly introduced vulnerabilities, verified remediations, and configuration transitions:

```bash
vulnscan diff \
  --baseline ./reports/web01-20261101-baseline.json \
  --current ./reports/web01-20261120-current.json \
  --output-dir ./reports

# Generates:
# - scan-diff-<timestamp>.json
# - scan-diff-<timestamp>.html (visual remediation delta report)
```

### 7. Report Branding & Scan Depth Profiles
Personalize reports with corporate classification headers, organization names, and auditor details, or customize the collection depth:

```bash
vulnscan scan-local \
  --company "Acme Cyber Defense" \
  --assessor "SecOps Assessment Team" \
  --classification "STRICTLY CONFIDENTIAL" \
  --depth deep \
  --output-dir ./reports
```

- `--depth basic`: Fast package and open ports inspection.
- `--depth standard` (default): Basic + systemd services, NGINX `nginx -T`, JVM intrinsics, CPU `/proc/cpuinfo` flags.
- `--depth deep`: Standard + unmanaged process discovery (`/proc/*/exe`), OpenSSH daemon audit (`sshd -T`), and Linux kernel `sysctl` security parameters.

### 8. Launch the Interactive Web Dashboard
Starts the built-in, zero-dependency web dashboard:

```bash
vulnscan serve --port 8080
```
Open `http://localhost:8080` in your browser to view findings, trigger scans, filter by severity/status, and download reports.

### 9. Launch the Streamlit UI
```bash
streamlit run vulnscan/ui/streamlit_app.py
```

### 10. Ingest & Auto-Fetch New CVEs from Online Feeds
Automatically queries authoritative online threat feeds (Red Hat Security Data API, CISA KEV catalog, and FIRST EPSS) and ingests any specific CVE into the scanner's advisory database with complete Section A–G assessment metadata:

```bash
# Fetch and ingest a specific CVE online
vulnscan fetch-cve --cve CVE-2023-38408

# Or using the launcher script
bash run.sh fetch-cve --cve CVE-2023-38408

# Ingest multiple CVEs for EL9
bash run.sh fetch-cve --cve CVE-2023-38408,CVE-2024-6387 --target-os el9

# Or run the standalone script directly
python3 scripts/update_advisory.py --cve CVE-2023-38408
```

---

## Reference Vulnerability Scenarios

The tool was evaluated against three authoritative reference CVE scenarios on Rocky Linux 9.6 (`platform:el9`):

### Scenario 1: CVE-2026-114938 (OpenJDK AVX-512 Base64 Decoding Vulnerability)
- **Component**: `java-17-openjdk` (17.0.8 installed; vendor fixed in `1:17.0.9-1.el9`).
- **Prerequisites**:
  1. CPU instruction flag `avx512_vbmi` present.
  2. JVM intrinsic `-XX:-UseBase64Intrinsics` must **not** be set.
- **Engine Logic**:
  - If CPU has `avx512_vbmi` and default JVM flags -> **`Affected`** (Score: 41.2).
  - If CPU lacks `avx512_vbmi` -> **`Not affected`** (Hardware cannot execute vulnerable intrinsic).
  - If `-XX:-UseBase64Intrinsics` is configured -> **`Mitigated`** (Vulnerable intrinsic deactivated).
  - If updated package `17.0.9-1.el9` is installed -> **`Fixed`** (EVR >= fixed release).

### Scenario 2: CVE-2026-123633 & CVE-2026-123007 (NGINX HTTP/2 Vulnerabilities)
- **Component**: `nginx` (1.20.1-14.el9_2.1 installed; vendor fixed in `1:1.20.1-14.el9_2.3`).
- **Prerequisites**:
  1. `nginx` systemd service must be running.
  2. HTTP/2 protocol must be active on listening port (`listen ... http2;` or `http2 on;`).
- **Engine Logic**:
  - If running with HTTP/2 enabled -> **`Affected`** (Score: 61.2).
  - If HTTP/2 parameter is absent from config -> **`Mitigated`** (Underlying package vulnerable, but attack surface closed).
  - If `nginx` daemon is stopped -> **`Potentially affected`** (Unpatched binary present, but daemon inactive).
  - If vendor package `1.20.1-14.el9_2.3` is installed -> **`Fixed`** (Vendor backport verified).

### Scenario 3: CVE-2023-44487 (HTTP/2 Rapid Reset - CISA KEV)
- **Component**: `nginx` (1.20.1-14.el9_2.1).
- **KEV Status**: Actively exploited in the wild.
- **Engine Logic**: Flagged with highest priority (Rank #1, Score: 81.2) due to confirmed applicability + active CISA KEV exploit status.

### Scenario 4: CVE-2021-3156 (Sudo Baron Samedit)
- **Component**: `sudo` (1.9.5p2-14.el9 installed).
- **Engine Logic**: Even though CVSS is High and present in CISA KEV, the EVR comparison detects that `1.9.5p2-14.el9` incorporates the vendor security backport. Status is marked **`Fixed`** and risk priority score drops to **3.6**.

---

## Report Formats

The tool generates four standardized report artifacts:

| Format | File Extension | Intended Audience | Features |
| :--- | :--- | :--- | :--- |
| **HTML** | `.html` | Security Analysts, SysAdmins, DevOps | Interactive search, live filtering (Severity & Status), evidence drawers, printable stylesheet. |
| **PDF** | `.pdf` | CISO, Auditors, Customers | Professional layout, executive summary cards, detailed audit tables, page numbers, zero dependencies. |
| **JSON** | `.json` | DevSecOps, SIEM, CI/CD | Full machine-readable data model including system identity, findings array, raw evidence, and metrics. |
| **CSV** | `.csv` | Infrastructure Teams, Jira Ingestion | RFC 4180 spreadsheet with CVE ID, component, versions, status, scores, and remediation commands. |

Sample reports are located in `samples/`:
- `samples/sample_report.html`
- `samples/sample_report.pdf`
- `samples/sample_report.json`
- `samples/sample_report.csv`

---

## Automated Test Suite

The scanner comes with an automated test suite verifying version comparison, hardware analysis, configuration detection, scenario evaluations, and report generation:

```bash
export PYTHONPATH=.
python3 -m unittest discover -s tests -v
```

### Test Coverage Highlights:
- `test_evr.py`: RPM `rpmvercmp`, Debian `debvercmp`, tilde/caret semantics, and EVR comparison.
- `test_os_detector.py`: Rocky 9.6, Ubuntu 22.04, and CPU AVX-512 VBMI detection.
- `test_config_analyzer.py`: NGINX HTTP/2 directive detection, JVM flags, and secret redaction.
- `test_scenarios.py`: Validates all reference CVE scenarios (Affected, Mitigated, Fixed, Not Affected, and Potentially Affected).
- `test_reporters.py`: Validates generation and integrity of HTML, PDF, JSON, and CSV artifacts.

---

## Documentation & Comparative Whitepapers

- 📖 **[Operator Manual](docs/OPERATOR_MANUAL.md)**: End-to-end guide covering installation, CLI commands (`scan-local`, `scan-remote`, `scan-fleet`, `diff`, `fetch-cve`), configuration, and report interpretation.
- 🔬 **[Comparative Analysis: linux-vuln-scanner vs. Anchore Syft + Grype vs. Aqua Security Trivy](docs/COMPARISON_SYFT_GRYPE_TRIVY.md)**: In-depth technical whitepaper detailing architectural differences, 14-dimension evaluation matrix, false-positive reduction analysis, and 5 empirical scenario breakdowns.

---

## Security Limitations and Operational Considerations

1. **Read-Only Scope**: The scanner will never apply updates or alter configurations. Remediation commands are provided for human operator review and execution.
2. **Ephemeral Containers**: Software running inside ephemeral Docker/Podman containers spawned after the scan window will not be reflected in the host inventory.
3. **Binary Renaming & Stripped Binaries**: Manually compiled binaries stripped of symbols or version banners may require manual version entry if no standard flags (`--version`, `-v`) are supported.
4. **Offline Mode & Data Freshness**: When running offline, the scanner relies on the local cache and bundled vendor seed database. The report clearly indicates offline mode and cache timestamps to prevent false claims of real-time intelligence.
5. **Least-Privilege Remote SSH**: When scanning remotely, run as a dedicated read-only audit user. If `sudo` is required for `nginx -T`, restrict sudo permissions in `/etc/sudoers` strictly to the required read-only commands:
   ```sudoers
   vulnaudit ALL=(ALL) NOPASSWD: /usr/sbin/nginx -T, /usr/bin/rpm, /usr/bin/dnf updateinfo *
   ```
