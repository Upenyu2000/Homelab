# SentinelForge Homelab

A runnable, evidence-first SOC, third-party risk and identity governance portfolio project.

## What it demonstrates

- SOC investigation workflow with timelines, IOCs, MITRE ATT&CK mapping and incident reports
- Third-party vendor onboarding, questionnaire scoring, SOC 2 review notes and risk acceptance memos
- Joiner/Mover/Leaver identity audits, orphaned-account checks and excessive-permission findings
- Executive dashboard and downloadable Markdown reports
- Safe synthetic data generation for a portfolio-ready demonstration

> This project is intentionally designed for an isolated homelab. Do not point simulations at systems you do not own or have permission to test.

## Run locally

```bash
git clone https://github.com/Upenyu2000/Homelab.git
cd Homelab
cp .env.example .env
docker compose up --build
```

Open `http://localhost:8501`.

Without Docker:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Modules

1. **SOC Investigation** — create and review cases, evidence, timeline events, IOCs and ATT&CK techniques.
2. **Vendor Risk** — assess a fictional SaaS vendor using weighted controls and generate an executive decision memo.
3. **Identity JML Audit** — analyse synthetic Entra ID-style records for leavers, stale accounts, missing MFA and risky access.
4. **Reports** — export complete Markdown evidence packs suitable for GitHub or interview discussion.

## Repository map

```text
app.py                         Streamlit interface
src/database.py                SQLite schema and persistence
src/services.py                Scoring, audit and report logic
src/seed.py                    Synthetic portfolio demonstration data
templates/                     Professional report templates
sample_data/                   Safe example input files
scripts/                       Import and validation utilities
docs/                          Architecture, runbook and frameworks
cases/                         Generated investigation evidence packs
vendor-risk/                   Generated vendor assessments
identity-audit/                Generated identity audits
```

## Portfolio walkthrough

1. Start the application and select **Load demo data**.
2. Open `CASE-001` and explain the detection, investigation timeline, IOCs and ATT&CK mapping.
3. Open the vendor assessment and explain inherent risk, control gaps, residual risk and conditional approval.
4. Run the identity audit and explain how Joiner/Mover/Leaver failures create access risk.
5. Export all three reports and commit the generated evidence packs.

## Framework alignment

- NIST Cybersecurity Framework 2.0
- NIST SP 800-61 incident handling lifecycle
- MITRE ATT&CK Enterprise
- CIS Controls v8
- ISO/IEC 27001 control themes
- NIST SP 800-53 access-control concepts

## Important limitation

The included events, identities, vendors and IOCs are fictional. Replace them only with authorised lab data and redact secrets before committing evidence.

## Licence

MIT
