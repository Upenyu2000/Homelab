from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from src.database import initialise, rows
from src.seed import seed_demo
from src.services import incident_report, identity_report, run_identity_audit, vendor_report

st.set_page_config(page_title="SentinelForge", page_icon="🛡️", layout="wide")
initialise()
seed_demo()

st.title("🛡️ SentinelForge")
st.caption("Enterprise SOC, incident response, third-party risk and identity governance homelab")

page = st.sidebar.radio("Workspace", ["Executive Dashboard", "SOC Investigations", "Vendor Risk", "Identity Governance", "Architecture & Runbook"])

if page == "Executive Dashboard":
    incidents = pd.DataFrame(rows("SELECT * FROM incidents"))
    vendors = pd.DataFrame(rows("SELECT * FROM vendors"))
    findings = pd.DataFrame(rows("SELECT * FROM identity_findings"))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Open investigations", int((incidents.status != "Closed").sum()))
    c2.metric("Critical incidents", int((incidents.severity == "Critical").sum()))
    c3.metric("Vendor residual risk", int(vendors.residual_risk.mean()) if not vendors.empty else 0)
    c4.metric("Identity findings", len(findings))
    left, right = st.columns(2)
    with left:
        st.plotly_chart(px.histogram(incidents, x="severity", title="Incidents by severity", category_orders={"severity":["Low","Moderate","High","Critical"]}), use_container_width=True)
    with right:
        attack = pd.DataFrame(rows("SELECT technique_id, technique, COUNT(*) AS cases FROM attack_map GROUP BY technique_id, technique ORDER BY cases DESC"))
        st.plotly_chart(px.bar(attack, x="technique_id", y="cases", hover_data=["technique"], title="MITRE ATT&CK coverage"), use_container_width=True)
    st.subheader("Case register")
    st.dataframe(incidents[["case_id","title","severity","status","owner","detected_at"]], use_container_width=True, hide_index=True)

elif page == "SOC Investigations":
    cases = rows("SELECT case_id,title,severity,status FROM incidents ORDER BY case_id")
    selected = st.selectbox("Investigation", [x["case_id"] for x in cases], format_func=lambda cid: f"{cid} — {next(x['title'] for x in cases if x['case_id']==cid)}")
    incident = rows("SELECT * FROM incidents WHERE case_id=?", (selected,))[0]
    c1, c2, c3 = st.columns(3)
    c1.metric("Severity", incident["severity"])
    c2.metric("Status", incident["status"])
    c3.metric("Owner", incident["owner"])
    st.info(incident["summary"])
    tabs = st.tabs(["Timeline", "IOCs", "MITRE ATT&CK", "Report"])
    with tabs[0]: st.dataframe(rows("SELECT event_time,source,event,evidence_ref FROM timeline WHERE case_id=? ORDER BY event_time", (selected,)), use_container_width=True, hide_index=True)
    with tabs[1]: st.dataframe(rows("SELECT type,value,context FROM iocs WHERE case_id=?", (selected,)), use_container_width=True, hide_index=True)
    with tabs[2]: st.dataframe(rows("SELECT technique_id,technique,evidence FROM attack_map WHERE case_id=?", (selected,)), use_container_width=True, hide_index=True)
    with tabs[3]:
        report = incident_report(selected)
        st.markdown(report)
        st.download_button("Download incident report", report, file_name=f"{selected}-incident-report.md")

elif page == "Vendor Risk":
    vendors = rows("SELECT * FROM vendors ORDER BY vendor_id")
    vendor_id = st.selectbox("Vendor", [v["vendor_id"] for v in vendors])
    v = next(x for x in vendors if x["vendor_id"] == vendor_id)
    c1, c2, c3 = st.columns(3)
    c1.metric("Inherent risk", f"{v['inherent_risk']}/100")
    c2.metric("Control score", f"{v['control_score']}/100")
    c3.metric("Residual risk", f"{v['residual_risk']}/100")
    st.subheader(v["name"])
    st.write(f"**Service:** {v['service']}  \n**Data:** {v['data_classification']}  \n**Decision:** {v['decision']}")
    st.markdown("### Material gaps")
    st.markdown(v["gaps"])
    st.markdown("### Remediation asks")
    st.markdown(v["remediation"])
    report = vendor_report(vendor_id)
    st.download_button("Download vendor assessment", report, file_name=f"{vendor_id}-risk-assessment.md")

elif page == "Identity Governance":
    if st.button("Run JML audit", type="primary"):
        run_identity_audit()
        st.success("Audit completed.")
    identities = rows("SELECT user_id,display_name,department,employment_status,account_enabled,mfa_enabled,privileged,last_sign_in,groups_csv FROM identities")
    findings = rows("SELECT finding_id,user_id,finding_type,severity,detail,recommendation FROM identity_findings")
    st.subheader("Identity inventory")
    st.dataframe(identities, use_container_width=True, hide_index=True)
    st.subheader("Audit findings")
    st.dataframe(findings, use_container_width=True, hide_index=True)
    report = identity_report()
    st.download_button("Download identity audit", report, file_name="identity-lifecycle-audit.md")

else:
    st.markdown("""
## Lab topology

```mermaid
flowchart TD
    K[Kali attack VM] --> LAN[Isolated lab network]
    LAN --> DC[Windows Server / AD DS / DNS]
    LAN --> WIN[Windows 11 / Sysmon]
    LAN --> LNX[Ubuntu / auditd]
    DC --> W[Wazuh SIEM]
    WIN --> W
    LNX --> W
    W --> P[SentinelForge investigation platform]
    P --> IR[Incident reports]
    P --> VR[Vendor risk assessments]
    P --> IAM[Identity audits]
```

## Safe execution sequence

1. Build an isolated host-only or internal virtual network.
2. Deploy Wazuh and enrol only authorised lab endpoints.
3. Enable Windows Security logging, Sysmon and Linux auditd.
4. Generate benign simulations or replay synthetic logs.
5. Investigate alerts, preserve evidence and map observations to MITRE ATT&CK.
6. Export reports from this platform and commit sanitised outputs to the repository.

Never expose intentionally vulnerable systems directly to the internet.
""")
