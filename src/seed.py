from __future__ import annotations

from datetime import datetime, timedelta, timezone
from .database import execute, execute_many, rows
from .services import calculate_vendor_risk

INCIDENTS = [
("CASE-001","Brute force and lateral movement","Critical","Contained","Upenyu Hlangabeza","2026-07-01T09:15:00+00:00","Repeated authentication failures from a Kali lab host were followed by a successful logon, encoded PowerShell, persistence and remote service activity.","Weak lab password and unrestricted east-west administration paths.","Disabled the affected account, isolated the endpoint, removed persistence, rotated credentials and blocked the source host.","Enforce MFA, account lockout, tiered administration, PowerShell logging and segmentation."),
("CASE-002","Ransomware simulation","Critical","Closed","Upenyu Hlangabeza","2026-07-03T11:40:00+00:00","A safe simulator created rapid file-renaming activity, a scheduled task and a ransom-note artefact on the Windows client.","User execution of an untrusted lab payload and insufficient application control.","Isolated the host, terminated the simulator, removed the task and restored test files from snapshot.","Deploy application control, protected backups, canary files and mass-modification detection."),
("CASE-003","Credential dumping behaviour","High","Contained","Upenyu Hlangabeza","2026-07-05T14:20:00+00:00","An authorised Atomic-style test generated suspicious access to LSASS and subsequent alternate-credential logons.","Excessive local administration and weak credential isolation.","Stopped the process, captured volatile evidence, rotated credentials and enabled additional endpoint controls.","Use Credential Guard, remove local admin, protect LSASS and alert on Sysmon Event ID 10."),
("CASE-004","Insider data exfiltration","High","Investigating","Upenyu Hlangabeza","2026-07-07T16:05:00+00:00","A fictional employee copied a large confidential dataset to removable media and a cloud-sync folder shortly before leaving.","Missing DLP controls and delayed leaver notification.","Suspended the account, preserved endpoint evidence and blocked external sharing.","Integrate HR offboarding, restrict USB, deploy DLP and monitor unusual download volume."),
("CASE-005","Macro to command-and-control chain","Critical","Closed","Upenyu Hlangabeza","2026-07-09T08:32:00+00:00","A benign macro simulation spawned PowerShell, created registry persistence and contacted a local test listener.","Office child processes were not restricted.","Quarantined the document, removed persistence and blocked the local test destination.","Block Office child processes, disable internet macros and deploy behavioural detections."),
]


def seed_demo() -> None:
    if rows("SELECT case_id FROM incidents LIMIT 1"):
        return
    execute_many("INSERT INTO incidents(case_id,title,severity,status,owner,detected_at,summary,root_cause,containment,recommendations) VALUES(?,?,?,?,?,?,?,?,?,?)", INCIDENTS)
    timelines = [
("CASE-001","2026-07-01T09:00:00Z","Windows Security","Twenty failed network logons from 10.10.20.50","EVT-4625"),
("CASE-001","2026-07-01T09:07:00Z","Windows Security","Successful logon for lab-admin from same source","EVT-4624"),
("CASE-001","2026-07-01T09:10:00Z","Sysmon","Encoded PowerShell launched from cmd.exe","SYS-001"),
("CASE-001","2026-07-01T09:12:00Z","Sysmon","New Run key created for persistence","SYS-013"),
("CASE-001","2026-07-01T09:14:00Z","Windows System","Remote service created on FILE01","EVT-7045"),
("CASE-002","2026-07-03T11:38:00Z","Sysmon","Burst of file writes and extension changes","SYS-011"),
("CASE-002","2026-07-03T11:39:00Z","Task Scheduler","Suspicious recurring task created","EVT-4698"),
("CASE-003","2026-07-05T14:18:00Z","Sysmon","Unsigned process accessed lsass.exe","SYS-010"),
("CASE-004","2026-07-07T15:52:00Z","DLP simulator","1,024 confidential files copied to USB","DLP-001"),
("CASE-005","2026-07-09T08:30:00Z","Sysmon","WINWORD.EXE spawned powershell.exe","SYS-001"),
]
    execute_many("INSERT INTO timeline(case_id,event_time,source,event,evidence_ref) VALUES(?,?,?,?,?)", timelines)
    execute_many("INSERT INTO iocs(case_id,type,value,context) VALUES(?,?,?,?)", [
("CASE-001","IPv4","10.10.20.50","Authorised Kali lab host"),("CASE-001","Account","lab-admin","Compromised lab identity"),
("CASE-002","Filename","READ_ME_LAB.txt","Benign ransom-note marker"),("CASE-003","Process","credential-test.exe","Safe test binary name"),
("CASE-004","Device","USB-LAB-001","Synthetic removable-media identifier"),("CASE-005","Domain","c2.lab.local","Local-only test listener")])
    execute_many("INSERT INTO attack_map(case_id,technique_id,technique,evidence) VALUES(?,?,?,?)", [
("CASE-001","T1110","Brute Force","Repeated 4625 failures"),("CASE-001","T1059.001","PowerShell","Encoded command line"),("CASE-001","T1021.002","SMB/Windows Admin Shares","Remote service activity"),
("CASE-002","T1486","Data Encrypted for Impact","Mass file changes"),("CASE-003","T1003.001","LSASS Memory","Process access telemetry"),
("CASE-004","T1052.001","Exfiltration over USB","Large removable-media copy"),("CASE-005","T1204.002","Malicious File","Macro execution simulation"),("CASE-005","T1547.001","Registry Run Keys","Persistence entry")])
    control = 58
    execute("INSERT INTO vendors(vendor_id,name,service,data_classification,business_owner,inherent_risk,control_score,residual_risk,decision,gaps,remediation) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("VEN-001","NimbusHR Cloud","HR SaaS platform","Confidential / personal data","People Operations",88,control,calculate_vendor_risk(88,control),"Conditional Approval","- No current penetration-test summary\n- Subprocessor list lacks change notification\n- Recovery test evidence is over 12 months old","- Provide current penetration-test attestation\n- Add contractual subprocessor notification\n- Complete and evidence a recovery exercise within 60 days"))
    old = (datetime.now(timezone.utc)-timedelta(days=130)).isoformat()
    execute_many("INSERT INTO identities(user_id,display_name,department,employment_status,account_enabled,mfa_enabled,privileged,last_sign_in,manager,groups_csv) VALUES(?,?,?,?,?,?,?,?,?,?)", [
("USR-001","Amina Patel","Finance","Joiner",1,1,0,datetime.now(timezone.utc).isoformat(),"FIN-MGR","Finance-Users"),
("USR-002","Ben Carter","Security","Mover",1,1,1,datetime.now(timezone.utc).isoformat(),"SEC-MGR","Security-Analysts,Old-Department"),
("USR-003","Chipo Dube","Sales","Leaver",1,0,0,old,"","Sales-Users,CRM-Export"),
("USR-004","Daniel Evans","IT","Active",1,0,1,old,"IT-MGR","Global-Admins"),
("USR-005","Eva Mensah","Operations","Active",0,1,0,old,"OPS-MGR","Operations-Users")])
