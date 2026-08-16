import streamlit as st
import json
import os
import pandas as pd
import html
from typing import List, Dict, Any

# Set page configurations
st.set_page_config(
    page_title="GCP Post-Quantum Compliance Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for modern styling
st.markdown("""
<style>
    .metric-card {
        background-color: #0f172a;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #1e293b;
        color: #f8fafc;
    }
    .report-card {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 12px;
        border-left: 5px solid #ef4444;
    }
    .compliant-card {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 12px;
        border-left: 5px solid #10b981;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ GCP Post-Quantum Cryptography Migration Dashboard")
st.markdown("Assess readiness, analyze HNDL threats, and plan cryptographic migration schedules for GCP projects.")

# Sidebar for controls & upload
st.sidebar.header("📁 Report Source")
uploaded_file = st.sidebar.file_uploader("Upload pqc_compliance_report.json", type=["json"])

findings_file = "pqc_compliance_report.json"
findings: list[Dict[str, Any]] = []

if uploaded_file is not None:
    try:
        findings = json.load(uploaded_file)
        st.sidebar.success("Loaded uploaded report.")
    except Exception as e:
        st.sidebar.error(f"Failed to load file: {e}")
elif os.path.exists(findings_file):
    try:
        with open(findings_file, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception:
        pass

# Fallback defaults if no report is loaded
if not findings:
    findings = [
        {
            "resource_name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-rsa",
            "resource_type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
            "status": "NON_PQC_COMPLIANT",
            "severity": "CRITICAL",
            "recommendation": "Configure software hybrid key-wrapping pattern using classical HSM wrappers.",
            "hndl_priority": "IMMEDIATE",
            "raw_metadata": {}
        },
        {
            "resource_name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/pqc-wrapped-hybrid",
            "resource_type": "kms.CryptoKey",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "status": "PQC_COMPLIANT",
            "severity": "NONE",
            "recommendation": "Compliant.",
            "hndl_priority": "LOW",
            "raw_metadata": {}
        },
        {
            "resource_name": "//compute.googleapis.com/projects/pqc-demo-project/global/sslPolicies/legacy-tls-policy",
            "resource_type": "compute.SslPolicy",
            "algorithm": "TLS_1_1",
            "status": "NON_PQC_COMPLIANT",
            "severity": "HIGH",
            "recommendation": "Upgrade SSL Policy min TLS version to TLS 1.3 to enforce post-quantum friendly key exchanges.",
            "hndl_priority": "HIGH",
            "raw_metadata": {}
        }
    ]

# Summary metrics
total_assets = len(findings)
compliant_count = sum(1 for f in findings if f.get("status") == "PQC_COMPLIANT")
non_compliant_count = total_assets - compliant_count
critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
pqc_ready_percentage = int((compliant_count / total_assets) * 100) if total_assets > 0 else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Inspected Assets", total_assets)
with m2:
    st.metric("PQC Compliant", compliant_count)
with m3:
    st.metric("Critical Quantum Risks", critical_count)
with m4:
    st.metric("PQC Readiness Score", f"{pqc_ready_percentage}%")

st.markdown("---")

# Layout: Scanner Findings on Left, Tools/Exporters on Right
left_col, right_col = st.columns([2, 1])

with left_col:
    st.subheader("📋 Audited Assets & Compliance Registry")
    
    # Priority Filters
    filter_severity = st.multiselect("Filter by Severity", options=["CRITICAL", "HIGH", "MEDIUM", "NONE"], default=["CRITICAL", "HIGH", "MEDIUM", "NONE"])
    
    for f in findings:
        sev = html.escape(f.get("severity", "NONE"))
        if sev not in filter_severity:
            continue
            
        is_compliant = f.get("status") == "PQC_COMPLIANT"
        card_class = "compliant-card" if is_compliant else "report-card"
        status_label = "PQC COMPLIANT" if is_compliant else "NON-COMPLIANT"
        status_color = "green" if is_compliant else "red"
        
        res_name = html.escape(f.get('resource_name', ''))
        res_type = html.escape(f.get('resource_type', ''))
        algo = html.escape(f.get('algorithm', ''))
        hndl_pri = html.escape(f.get('hndl_priority', 'MEDIUM'))
        rec = html.escape(f.get('recommendation', ''))
        
        st.markdown(f"""
        <div class="{card_class}">
            <h4>Resource: <code>{res_name}</code></h4>
            <p><b>Type:</b> <code>{res_type}</code> | <b>Algorithm:</b> <code>{algo}</code></p>
            <p><b>Readiness Status:</b> <span style="color:{status_color}; font-weight:bold;">{status_label}</span> (Severity: <b>{sev}</b> | HNDL Priority: <b>{hndl_pri}</b>)</p>
            <p><b>Recommendation:</b> {rec}</p>
        </div>
        """, unsafe_allow_html=True)

with right_col:
    st.subheader("🛠️ Migration Action Panel")
    
    # Export Actions
    st.write("### Export Scans")
    
    # Create Dataframe for exports
    df = pd.DataFrame(findings)
    if not df.empty and "raw_metadata" in df.columns:
        df = df.drop(columns=["raw_metadata"])
        
    csv_data = df.to_csv(index=False).encode('utf-8')
    json_data = json.dumps(findings, indent=2).encode('utf-8')
    
    # Markdown exporter logic
    md_report = "# GCP Post-Quantum Migration Audit Report\n\n"
    md_report += f"**Overall Readiness**: {pqc_ready_percentage}%\n"
    md_report += f"**Total Audited**: {total_assets} | **Compliant**: {compliant_count} | **Non-Compliant**: {non_compliant_count}\n\n"
    md_report += "## Findings Registry\n"
    for f in findings:
        md_report += f"### Resource: `{f.get('resource_name')}`\n"
        md_report += f"- **Type**: `{f.get('resource_type')}`\n"
        md_report += f"- **Status**: {f.get('status')} (Severity: {f.get('severity')})\n"
        md_report += f"- **Recommendation**: {f.get('recommendation')}\n\n"
    
    st.download_button("Download CSV Report", csv_data, "pqc_audit_report.csv", "text/csv")
    st.download_button("Download JSON Report", json_data, "pqc_audit_report.json", "application/json")
    st.download_button("Download Markdown Audit Summary", md_report.encode('utf-8'), "pqc_audit_report.md", "text/markdown")
    
    # CycloneDX 1.6+ CBOM Exporter
    try:
        import sys
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
        from gcp_pqc_inventory_scanner import generate_cbom
        cbom_dict = generate_cbom(findings)
        cbom_json_data = json.dumps(cbom_dict, indent=2).encode('utf-8')
        st.download_button("Download CycloneDX 1.6+ CBOM JSON", cbom_json_data, "pqc_cbom.json", "application/json")
    except Exception as e:
        st.warning(f"Failed to load CBOM exporter: {e}")
    
    st.markdown("---")
    st.write("### HNDL Risk Prioritization Index")
    st.info("Prioritize keys wrapping long-lived sensitive datasets (Data Longevity > 5 years) first, as they are targets of Harvest Now, Decrypt Later campaigns.")
    
    # Simple interactive calculation helper
    longevity = st.slider("Target Data Longevity (Years)", min_value=1, max_value=30, value=10)
    if longevity >= 10:
        st.error("Priority: IMMEDIATE. Implement hybrid wrap policies immediately.")
    elif longevity >= 5:
        st.warning("Priority: HIGH. Plan migration wrappers within 12 months.")
    else:
        st.success("Priority: MEDIUM/LOW. Schedule transition in standard roadmap.")
