# Incident Response Runbook

## 1. Preparation

- Confirm lab scope, asset owner and authorisation.
- Synchronise system clocks.
- Enable PowerShell script-block logging, process creation auditing and Sysmon.
- Record evidence hashes and preserve original logs read-only.

## 2. Detection and triage

1. Record alert source, time, affected identity and asset.
2. Validate the alert against raw telemetry.
3. Assign severity using business impact, privilege, exposure and confidence.
4. Open a case and preserve volatile evidence where justified.

## 3. Investigation

- Build a timestamped timeline in UTC.
- Identify initial access, execution, persistence, privilege escalation, lateral movement and impact.
- Record IOCs with context; do not treat an indicator alone as proof.
- Map only evidenced behaviour to MITRE ATT&CK.
- Separate facts, assumptions and unanswered questions.

## 4. Containment

- Isolate affected endpoints.
- Disable or restrict compromised identities.
- Block confirmed malicious infrastructure.
- Preserve evidence before destructive remediation where possible.

## 5. Eradication and recovery

- Remove persistence and unauthorised tooling.
- Rotate exposed credentials and revoke sessions.
- Restore from a known-good snapshot or backup.
- Validate logging, controls and service health before reconnecting.

## 6. Closure

The report must contain an executive summary, scope, timeline, evidence references, IOCs, ATT&CK mapping, root cause, containment, recovery, recommendations and lessons learned.

## Severity guide

| Severity | Meaning |
|---|---|
| Critical | Active compromise, privileged access, material data loss or widespread impact |
| High | Confirmed malicious activity with contained or limited impact |
| Moderate | Suspicious activity requiring investigation but without confirmed compromise |
| Low | Informational or low-risk control issue |
