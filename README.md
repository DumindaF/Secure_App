# DevSecOps Threat Detection Pipeline

**Student:** Duminda Fernando | **ID:** S10680634  
<<<<<<< HEAD
**Course:** CYB6005 — Cybersecurity Project  
=======
**Course:** CYB6005 — Cybersecurity Capstone Project  
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
**Methodology:** OWASP Threat Modeling + STRIDE Framework

---

## Overview

<<<<<<< HEAD
This project implements an automated threat detection pipeline integrated into a DevSecOps (CI/CD) workflow. It applies the OWASP Threat Modeling methodology and STRIDE framework to systematically identify, classify, and report security threats in a web application — before code reaches production.
=======
This project implements an automated threat detection pipeline integrated into a DevSecOps (CI/CD) workflow. It applies the OWASP Threat Modeling methodology and STRIDE framework to systematically identify, classify, and report security threats in a sample web application — before code reaches production.
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063

The pipeline scans source code at commit time for hardcoded secrets, vulnerable dependencies, and static analysis findings, then maps each finding to a STRIDE threat category and generates a structured HTML threat report.

---

## Project Structure

```
Secure_App-main/
├── pipeline/
│   ├── code vulnerable_app.py      # Intentionally vulnerable sample app (scan target)
│   ├── scanner.py                  # Core pipeline — runs all 3 scans + STRIDE mapping
│   └── Secure App Pipeline.json   # OWASP Threat Dragon threat model (DFD)
├── reports/
│   ├── report_generator.py         # Generates HTML threat report from scan results
│   └── threat_report.html          # Pre-generated sample report output
├── threat_model/
│   └── threat_model.pdf            # Exported Threat Dragon DFD diagram (PDF)
└── README.md
```

---

## How It Works

The pipeline follows the OWASP 4-question Threat Modeling framework:

| Question | How It's Answered |
|---|---|
| What are we working on? | Modelled via Data Flow Diagram in OWASP Threat Dragon |
| What can go wrong? | STRIDE analysis across all trust boundaries and data flows |
| What are we going to do about it? | Automated scans enforce checks at the code level |
| Did we do a good enough job? | HTML report with severity ratings and mitigations |

### Pipeline Flow

```
Code Commit
    │
    ▼
[Bandit]          ← Static analysis (SAST) — finds code-level vulnerabilities
    │
    ▼
[detect-secrets]  ← Scans for hardcoded secrets, API keys, passwords
    │
    ▼
[pip-audit]       ← Checks dependencies for known CVEs
    │
    ▼
[STRIDE Mapper]   ← Classifies each finding into a STRIDE threat category
    │
    ▼
[Report Generator] ← Produces HTML report with severity summary + findings table
```

---

## Tools Used

| Tool | Purpose | STRIDE Category Targeted |
|---|---|---|
| Bandit | Python static analysis (SAST) | Information Disclosure, Tampering |
| detect-secrets | Hardcoded secret detection | Information Disclosure |
| pip-audit | Dependency vulnerability scanning | Tampering |
| OWASP Threat Dragon | Threat modelling & DFD creation | All STRIDE categories |

---

<<<<<<< HEAD
## Project Progress

### Schedule Overview (6-Week Plan)

| Week | Deliverable | Status |
|---|---|---|
| Week 1 | Project proposal, scope definition, OWASP framework selection | ✅ Complete |
| Week 2 | Threat modelling — OWASP Threat Dragon DFD, trust boundary mapping | ✅ Complete |
| Week 3 | Pipeline development — Bandit, detect-secrets, pip-audit integration | ✅ Complete |
| Week 4 | STRIDE mapper, report generator, vulnerable sample app | ✅ Complete |
| Week 5 | README documentation, GitHub repository setup, integration testing | ✅ Complete |
| Week 6 | Final presentation & submission *(current)* | 🔄 In Progress |

### GANTT Chart

| Task | Wk 1 | Wk 2 | Wk 3 | Wk 4 | Wk 5 | Wk 6 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Project proposal & scope | 🟩 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Threat modelling (DFD) | 🟩 | 🟩 | ⬜ | ⬜ | ⬜ | ⬜ |
| Pipeline development | ⬜ | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
| STRIDE mapping | ⬜ | ⬜ | 🟩 | 🟩 | ⬜ | ⬜ |
| HTML report generator | ⬜ | ⬜ | ⬜ | 🟩 | 🟩 | ⬜ |
| README & GitHub setup | ⬜ | ⬜ | ⬜ | ⬜ | 🟩 | 🟩 |
| Final presentation & submission | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟦 |

> 🟩 Complete &nbsp;&nbsp; 🟦 In progress &nbsp;&nbsp; ⬜ Not started

### Completed Milestones

- **Week 1** — Project proposal submitted; OWASP Threat Modeling methodology selected
- **Week 3** — Prototype v1 complete; all three scanning tools operational
- **Week 5** — Fully working pipeline with STRIDE mapping and HTML report generation
- **Week 6** — Final presentation and project submission *(current milestone)*

### Challenges & How They Were Addressed

**1. pip-audit environment dependency**  
`pip-audit` scans the currently active Python environment rather than a `requirements.txt` file, meaning results depend on what packages are installed at the time of scanning. This was noted as a limitation and is documented in the Limitations section. A planned improvement for Week 7 is to pass a `requirements.txt` directly to `pip-audit` for consistent, environment-independent scanning.

**2. Duplicated scan logic across scripts**  
The scan functions and `map_to_stride()` logic were initially duplicated between `scanner.py` and `report_generator.py`. This was identified during Week 5 code review. The STRIDE mapping functions have since been aligned, and consolidation into a shared module is planned for Week 7.

**3. STRIDE coverage gaps**  
The current pipeline detects Tampering and Information Disclosure well, but Spoofing, Repudiation, Denial of Service, and Elevation of Privilege are not yet covered by the automated scans. Expanding coverage — particularly for Spoofing and EoP — is planned for Week 7.

---

## Setup & Installation

### Prerequisites
=======
## Setup & Installation

### Prerequisites

>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
- Python 3.8+
- pip

### Install Dependencies

```bash
pip install bandit detect-secrets pip-audit
```

### Run the Scanner

```bash
cd pipeline
python scanner.py
```

This will scan `code vulnerable_app.py` and print findings to the terminal.

### Generate the HTML Report

```bash
cd reports
python report_generator.py
```

This will produce `threat_report.html` in the `reports/` directory. Open it in any browser to view the full report.

---

## Sample Findings

The pipeline detects the following vulnerability types in the sample app:

| Severity | Finding | Tool | STRIDE Category |
|---|---|---|---|
| LOW | B105 — Hardcoded password string | Bandit | Information Disclosure |
| MEDIUM | B608 — SQL injection via string query | Bandit | Tampering |
| MEDIUM | B608 — SQL injection (second instance) | Bandit | Tampering |
| HIGH | Secret Keyword — API key detected | detect-secrets | Information Disclosure |
| HIGH | Secret Keyword — Password detected | detect-secrets | Information Disclosure |

---

## STRIDE Mapping Reference

| STRIDE Threat | Description | Example in This Project |
|---|---|---|
<<<<<<< HEAD
| Spoofing | Impersonating another user or system | Planned — Week 7 |
| Tampering | Modifying data without authorisation | SQL Injection (B608) |
| Repudiation | Denying actions without proof | Planned — Week 7 |
| Information Disclosure | Exposing data to unauthorised parties | Hardcoded credentials, API keys |
| Denial of Service | Making a system unavailable | Planned — Week 7 |
| Elevation of Privilege | Gaining higher access than permitted | Planned — Week 7 |
=======
| **S**poofing | Impersonating another user or system | N/A in current scope |
| **T**ampering | Modifying data without authorisation | SQL Injection (B608) |
| **R**epudiation | Denying actions without proof | N/A in current scope |
| **I**nformation Disclosure | Exposing data to unauthorised parties | Hardcoded credentials, API keys |
| **D**enial of Service | Making a system unavailable | N/A in current scope |
| **E**levation of Privilege | Gaining higher access than permitted | N/A in current scope |
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063

---

## Threat Model

<<<<<<< HEAD
The threat model was built using OWASP Threat Dragon v2.5.0 and covers the data flows of the sample web application including:

- User → Web Application (login, data retrieval)
- Web Application → SQLite Database (query execution)
=======
The threat model was built using **OWASP Threat Dragon v2.5.0** and covers the data flows of the sample web application including:

- **User → Web Application** (login, data retrieval)
- **Web Application → SQLite Database** (query execution)
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
- Trust boundaries between external users and internal data stores

The full DFD is available as:
- `pipeline/Secure App Pipeline.json` — editable Threat Dragon file
- `threat_model/threat_model.pdf` — exported PDF diagram

---

## Limitations & Future Work

- Currently scans Python files only — future versions could support JavaScript, Java, etc.
<<<<<<< HEAD
- `pip-audit` results depend on the environment's installed packages, not a `requirements.txt` — a future improvement would be to pass a requirements file directly
- STRIDE mapping could be expanded to cover Spoofing, Repudiation, DoS, and Elevation of Privilege
- Pipeline could be integrated into GitHub Actions for automated CI/CD triggering
- `scanner.py` and `report_generator.py` share duplicated scan logic — consolidation into a shared module would improve maintainability
=======
- `pip-audit` results depend on the environment's installed packages, not a `requirements.txt`
- STRIDE mapping could be expanded to cover Spoofing, Repudiation, DoS, and Elevation of Privilege
- Pipeline could be integrated into GitHub Actions for automated CI/CD triggering
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063

---

## References

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
<<<<<<< HEAD
- [pip-audit](https://github.com/pypa/pip-audit)
- [MITRE STRIDE Framework](https://attack.mitre.org/)
=======
- [pip-audit](https://pypi.org/project/pip-audit/)
- MITRE STRIDE Framework
>>>>>>> 06f5d71e2fcd536ad53cb087567815dae7174063
