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

# Setup sys.path to import verification modules
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
from verify_report import verify_signed_report

# Sidebar for controls & upload
st.sidebar.header("📁 Report Source")
uploaded_file = st.sidebar.file_uploader("Upload pqc_compliance_report.json / signed.json", type=["json"])

findings_file = "pqc_compliance_report.json"
signed_file = "pqc_compliance_report.signed.json"
findings: list[Dict[str, Any]] = []
attestation_status = "Unsigned"

def process_loaded_data(data):
    global findings, attestation_status
    if isinstance(data, dict) and "payload" in data and "signature" in data and "publicKey" in data:
        # It is a signed report envelope
        findings = data["payload"]
        is_valid = verify_signed_report(data)
        if is_valid:
            attestation_status = "Verified"
        else:
            attestation_status = "Invalid/Tampered"
    else:
        # Raw compliance report
        findings = data
        attestation_status = "Unsigned"

# Load report from upload or default files
if uploaded_file is not None:
    try:
        raw_data = json.load(uploaded_file)
        process_loaded_data(raw_data)
        if attestation_status == "Verified":
            st.sidebar.success("✅ Signature Verified. Untampered report.")
        elif attestation_status == "Invalid/Tampered":
            st.sidebar.error("❌ INVALID SIGNATURE! Report tampered.")
        else:
            st.sidebar.info("Loaded unsigned report.")
    except Exception as e:
        st.sidebar.error(f"Failed to load file: {e}")
else:
    # Try signed file first
    loaded = False
    for filename in [signed_file, findings_file]:
        if os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    process_loaded_data(raw_data)
                    loaded = True
                    break
            except Exception:
                pass
    if not loaded:
        # Fallback defaults if no file is present
        findings = [
            {
                "resource_name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-rsa",
                "resource_type": "kms.CryptoKey",
                "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
                "status": "NON_PQC_COMPLIANT",
                "severity": "CRITICAL",
                "recommendation": "Configure software hybrid key-wrapping pattern using classical HSM wrappers.",
                "hndl_priority": "IMMEDIATE",
                "crypto_classification": "CLASSICAL",
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
                "crypto_classification": "HYBRID",
                "raw_metadata": {}
            }
        ]

# Display attestation badge in the sidebar
st.sidebar.markdown("### Attestation Metadata")
if attestation_status == "Verified":
    st.sidebar.markdown("**Status:** :green[✅ Verified Attested Report]")
elif attestation_status == "Invalid/Tampered":
    st.sidebar.markdown("**Status:** :red[❌ TAMPERED / INVALID]")
else:
    st.sidebar.markdown("**Status:** :orange[⚠️ Unsigned]")

# Summary metrics
total_assets = len(findings)
compliant_count = sum(1 for f in findings if f.get("crypto_classification") in ["NATIVE_PQC", "HYBRID"])
non_compliant_count = total_assets - compliant_count
critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
pqc_ready_percentage = int((compliant_count / total_assets) * 100) if total_assets > 0 else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Inspected Assets", total_assets)
with m2:
    st.metric("PQC Compliant / Hybrid", compliant_count)
with m3:
    st.metric("Critical Quantum Risks", critical_count)
with m4:
    st.metric("PQC Maturity Score", f"{pqc_ready_percentage}%")

st.markdown("---")

# Layout: Tabs
tab1, tab2 = st.tabs(["📋 Audited Assets & Compliance Registry", "📈 Cryptographic Security Trends"])

with tab1:
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
            classification = html.escape(f.get('crypto_classification', 'CLASSICAL'))
            rec = html.escape(f.get('recommendation', ''))
            
            st.markdown(f"""
            <div class="{card_class}">
                <h4>Resource: <code>{res_name}</code></h4>
                <p><b>Type:</b> <code>{res_type}</code> | <b>Algorithm:</b> <code>{algo}</code> | <b>Classification:</b> <code>{classification}</code></p>
                <p><b>Readiness Status:</b> <span style="color:{status_color}; font-weight:bold;">{status_label}</span> (Severity: <b>{sev}</b> | HNDL Priority: <b>{hndl_pri}</b>)</p>
                <p><b>Recommendation:</b> {rec}</p>
            </div>
            """, unsafe_allow_html=True)

    with right_col:
        st.subheader("🛠️ Migration Action Panel")
        
        # Export Actions
        st.write("### Export Scans")
        
        df = pd.DataFrame(findings)
        if not df.empty and "raw_metadata" in df.columns:
            df = df.drop(columns=["raw_metadata"])
            
        csv_data = df.to_csv(index=False).encode('utf-8')
        json_data = json.dumps(findings, indent=2).encode('utf-8')
        
        # Markdown exporter logic
        md_report = "# GCP Post-Quantum Migration Audit Report\n\n"
        md_report += f"**PQC Maturity Score**: {pqc_ready_percentage}%\n"
        md_report += f"**Total Audited**: {total_assets} | **Compliant**: {compliant_count} | **Non-Compliant**: {non_compliant_count}\n\n"
        md_report += "## Findings Registry\n"
        for f in findings:
            md_report += f"### Resource: `{f.get('resource_name')}`\n"
            md_report += f"- **Type**: `{f.get('resource_type')}`\n"
            md_report += f"- **Classification**: `{f.get('crypto_classification')}`\n"
            md_report += f"- **Status**: {f.get('status')} (Severity: {f.get('severity')})\n"
            md_report += f"- **Recommendation**: {f.get('recommendation')}\n\n"
        
        st.download_button("Download CSV Report", csv_data, "pqc_audit_report.csv", "text/csv")
        st.download_button("Download JSON Report", json_data, "pqc_audit_report.json", "application/json")
        st.download_button("Download Markdown Audit Summary", md_report.encode('utf-8'), "pqc_audit_report.md", "text/markdown")
        
        # CycloneDX 1.6+ CBOM Exporter
        try:
            from gcp_pqc_inventory_scanner import generate_cbom
            cbom_dict = generate_cbom(findings)
            cbom_json_data = json.dumps(cbom_dict, indent=2).encode('utf-8')
            st.download_button("Download CycloneDX 1.6+ CBOM JSON", cbom_json_data, "pqc_cbom.json", "application/json")
        except Exception as e:
            st.warning(f"Failed to load CBOM exporter: {e}")
        
        # Verifiable Signed Report Exporter
        try:
            from report_attester import sign_findings_report
            signed_dict = sign_findings_report(findings)
            signed_json_data = json.dumps(signed_dict, indent=2).encode('utf-8')
            st.download_button("Download Verifiable Signed Report JSON", signed_json_data, "pqc_compliance_report.signed.json", "application/json")
        except Exception as e:
            st.warning(f"Failed to load attestation signer: {e}")

        st.markdown("---")
        st.write("### HNDL Risk Prioritization Index")
        st.info("Prioritize keys wrapping long-lived sensitive datasets (Data Longevity > 5 years) first, as they are targets of Harvest Now, Decrypt Later campaigns.")
        
        longevity = st.slider("Target Data Longevity (Years)", min_value=1, max_value=30, value=10)
        if longevity >= 10:
            st.error("Priority: IMMEDIATE. Implement hybrid wrap policies immediately.")
        elif longevity >= 5:
            st.warning("Priority: HIGH. Plan migration wrappers within 12 months.")
        else:
            st.success("Priority: MEDIUM/LOW. Schedule transition in standard roadmap.")

        st.markdown("---")
        # Policy-as-Code Remediation Panel
        st.write("### 🏗️ Policy-as-Code (PaC) Remediation")
        st.info("Generate and download Terraform configurations, Org Policies, and gcloud scripts to repair non-compliant keys.")
        
        try:
            sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
            from pqc_remediator import generate_remediation_plan
            import tempfile
            with tempfile.TemporaryDirectory() as tmp_dir:
                generate_remediation_plan(findings, tmp_dir)
                
                with open(os.path.join(tmp_dir, "remediate_infra.tf"), "r", encoding="utf-8") as f_in:
                    tf_infra_val = f_in.read()
                with open(os.path.join(tmp_dir, "remediate_org_policies.tf"), "r", encoding="utf-8") as f_in:
                    tf_policies_val = f_in.read()
                with open(os.path.join(tmp_dir, "remediate.sh"), "r", encoding="utf-8") as f_in:
                    sh_val = f_in.read()
                with open(os.path.join(tmp_dir, "remediation_plan.md"), "r", encoding="utf-8") as f_in:
                    plan_md_val = f_in.read()
                    
                st.download_button("Download Remediation Terraform (Infra)", tf_infra_val.encode('utf-8'), "remediate_infra.tf", "text/plain")
                st.download_button("Download Remediation Org Policies", tf_policies_val.encode('utf-8'), "remediate_org_policies.tf", "text/plain")
                st.download_button("Download Remediation Shell Script (gcloud)", sh_val.encode('utf-8'), "remediate.sh", "application/x-sh")
                
                # Show a preview of the Remediation Plan in an expander
                with st.expander("🔍 View Remediation Plan Preview"):
                    st.markdown(plan_md_val)
        except Exception as e:
            st.warning(f"Failed to generate remediation plan: {e}")


with tab2:
    st.subheader("📈 PQC Maturity & Posture Trends")
    st.markdown("Track post-quantum posture adjustments, key rotations, and compliance levels across scanner runs.")
    
    try:
        from drift_tracker import get_scan_history, check_for_drift
        project_id_key = "pqc-demo-project"
        history = get_scan_history(project_id_key)
        
        if history:
            df_hist = pd.DataFrame(history)
            df_hist['timestamp'] = pd.to_datetime(df_hist['timestamp'])
            
            # Show historical trend graph
            st.write("#### PQC Maturity Score Over Time")
            chart_df = df_hist.copy().rename(columns={"maturity_score": "Maturity Score (%)", "timestamp": "Scan Time"}).set_index("Scan Time")
            st.line_chart(chart_df["Maturity Score (%)"])
            
            # Compliance Drift Alert Panel
            drift_results = check_for_drift(project_id_key, findings)
            if drift_results["drift_detected"]:
                st.warning("### ⚠️ Compliance Drift Identified")
                if drift_results["previous_maturity_score"] is not None:
                    st.write(f"Maturity level regression: **{drift_results['previous_maturity_score']}% ➡️ {drift_results['new_maturity_score']}%** (delta: **{drift_results['score_delta']}%**)")
                if drift_results["newly_classical_assets"]:
                    st.write("**New Classical Assets Introduced:**")
                    for a in drift_results["newly_classical_assets"]:
                        st.write(f"- `{a}`")
                if drift_results["downgraded_assets"]:
                    st.write("**Downgraded Assets (PQC ➡️ Classical):**")
                    for a in drift_results["downgraded_assets"]:
                        st.write(f"- `{a}`")
            else:
                st.success("✅ No cryptographic policy or maturity drift detected in latest run.")
            
            st.write("#### Historical Scan Database Snapshots")
            st.dataframe(df_hist)
        else:
            st.info("No scan history recorded in SQLite yet. Run the scanner to log runs and visualize trends.")
    except Exception as e:
        st.error(f"Failed to load scan trends: {e}")

