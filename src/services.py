from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from .database import execute, rows


def risk_label(score: int) -> str:
    if score < 20: return "Low"
    if score < 50: return "Moderate"
    if score < 75: return "High"
    return "Critical"


def calculate_vendor_risk(inherent: int, control_score: int) -> int:
    inherent = max(0, min(100, int(inherent)))
    control_score = max(0, min(100, int(control_score)))
    return round(inherent * (1 - control_score / 100))


def run_identity_audit() -> list[dict]:
    identities = rows("SELECT * FROM identities ORDER BY user_id")
    execute("DELETE FROM identity_findings")
    findings, counter = [], 1
    now = datetime.now(timezone.utc)
    for i in identities:
        checks = []
        if i["employment_status"] == "Leaver" and i["account_enabled"]:
            checks.append(("Leaver account enabled", "Critical", "Departed worker retains an enabled account.", "Disable the account, revoke sessions and remove access immediately."))
        if i["privileged"] and not i["mfa_enabled"]:
            checks.append(("Privileged account without MFA", "Critical", "Privileged identity is not protected by MFA.", "Enforce phishing-resistant MFA and review role eligibility."))
        elif i["account_enabled"] and not i["mfa_enabled"]:
            checks.append(("MFA missing", "High", "Active account is not protected by MFA.", "Require MFA through Conditional Access."))
        if i["last_sign_in"] and i["account_enabled"]:
            age = (now - datetime.fromisoformat(i["last_sign_in"]).astimezone(timezone.utc)).days
            if age > 90:
                checks.append(("Stale active account", "High", f"No sign-in for {age} days.", "Confirm business need, then disable or recertify access."))
        if i["employment_status"] == "Mover" and "Old-Department" in i["groups_csv"]:
            checks.append(("Mover retained legacy access", "High", "User retains a previous-department group.", "Remove legacy membership and obtain manager recertification."))
        for finding_type, severity, detail, recommendation in checks:
            finding_id = f"IDF-{counter:03d}"
            execute("INSERT INTO identity_findings VALUES(NULL,?,?,?,?,?,?)", (finding_id, i["user_id"], finding_type, severity, detail, recommendation))
            findings.append({"finding_id": finding_id, "user_id": i["user_id"], "finding_type": finding_type, "severity": severity, "detail": detail, "recommendation": recommendation})
            counter += 1
    return findings


def incident_report(case_id: str) -> str:
    found = rows("SELECT * FROM incidents WHERE case_id=?", (case_id,))
    if not found: raise ValueError(f"Unknown case: {case_id}")
    i = found[0]
    timeline = rows("SELECT * FROM timeline WHERE case_id=? ORDER BY event_time", (case_id,))
    iocs = rows("SELECT * FROM iocs WHERE case_id=? ORDER BY type,value", (case_id,))
    attack = rows("SELECT * FROM attack_map WHERE case_id=? ORDER BY technique_id", (case_id,))
    tl = "\n".join(f"| {x['event_time']} | {x['source']} | {x['event']} | {x['evidence_ref']} |" for x in timeline) or "| - | - | No events | - |"
    io = "\n".join(f"| {x['type']} | `{x['value']}` | {x['context']} |" for x in iocs) or "| - | - | None |"
    at = "\n".join(f"| {x['technique_id']} | {x['technique']} | {x['evidence']} |" for x in attack) or "| - | - | None |"
    return f"""# Incident Report — {i['case_id']}: {i['title']}

## Executive summary
{i['summary']}

**Severity:** {i['severity']}  
**Status:** {i['status']}  
**Owner:** {i['owner']}  
**Detected:** {i['detected_at']}

## Timeline
| Time | Source | Event | Evidence |
|---|---|---|---|
{tl}

## Indicators of compromise
| Type | Value | Context |
|---|---|---|
{io}

## MITRE ATT&CK mapping
| Technique | Name | Evidence |
|---|---|---|
{at}

## Root cause
{i['root_cause']}

## Containment, eradication and recovery
{i['containment']}

## Recommendations and lessons learned
{i['recommendations']}
"""


def vendor_report(vendor_id: str) -> str:
    v = rows("SELECT * FROM vendors WHERE vendor_id=?", (vendor_id,))[0]
    return f"""# Third-Party Risk Assessment — {v['name']}

## Executive decision
**Decision:** {v['decision']}  
**Residual risk:** {v['residual_risk']}/100 ({risk_label(v['residual_risk'])})  
**Business owner:** {v['business_owner']}

## Scope
- Service: {v['service']}
- Data classification: {v['data_classification']}
- Inherent risk: {v['inherent_risk']}/100
- Control effectiveness: {v['control_score']}/100

## Material control gaps
{v['gaps']}

## Required remediation
{v['remediation']}

## Risk statement
The vendor may be onboarded only under the stated decision and remediation conditions. Evidence should be revalidated annually or after a material service change.
"""


def identity_report() -> str:
    findings = rows("SELECT * FROM identity_findings ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 ELSE 3 END, finding_id")
    table = "\n".join(f"| {f['finding_id']} | {f['user_id']} | {f['severity']} | {f['finding_type']} | {f['recommendation']} |" for f in findings) or "| - | - | - | No findings | - |"
    return f"""# Identity Lifecycle Audit

## Executive summary
The review tested joiner, mover and leaver records for offboarding failures, stale access, missing MFA and excessive privilege. **{len(findings)} findings** were identified.

## Findings
| ID | User | Severity | Finding | Recommendation |
|---|---|---|---|---|
{table}

## Control recommendations
1. Connect HR termination events to automated account disablement and token revocation.
2. Enforce phishing-resistant MFA for privileged and remote access.
3. Run quarterly access recertification and remove legacy mover permissions.
4. Alert on stale enabled accounts and accounts without a manager.
"""


def save_report(relative_path: str, content: str) -> Path:
    path = Path(relative_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
