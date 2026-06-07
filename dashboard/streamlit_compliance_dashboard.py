import streamlit as st
import json
import os

# Set page configurations
st.set_page_config(
    page_title="GCP Post-Quantum Compliance Dashboard",
    layout="wide"
)

st.title("🛡️ GCP Post-Quantum Cryptography Migration Dashboard")
st.markdown("Monitor post-quantum readiness, track cryptographic assets, and manage HNDL mitigation pathways.")

# Mock compliance data if JSON file is missing
findings_file = "pqc_compliance_report.json"
findings = []

if os.path.exists(findings_file):
    try:
        with open(findings_file, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception:
        pass

if not findings:
    findings = [
        {
            "resource": "locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-rsa",
            "type": "kms.CryptoKey",
            "status": "NON_PQC_COMPLIANT",
            "reason": "Uses legacy algorithm: RSA. Vulnerable to quantum decrypt.",
            "severity": "CRITICAL"
        },
        {
            "resource": "locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-ecc",
            "type": "kms.CryptoKey",
            "status": "NON_PQC_COMPLIANT",
            "reason": "Uses legacy algorithm: ECC.",
            "severity": "HIGH"
        },
        {
            "resource": "locations/us-central1/keyRings/ring-1/cryptoKeys/pqc-wrapped-hybrid",
            "type": "kms.CryptoKey",
            "status": "PQC_COMPLIANT",
            "reason": "Meets requirements via hybrid wrapping.",
            "severity": "NONE"
        },
        {
            "resource": "global/sslPolicies/legacy-tls-policy",
            "type": "compute.SslPolicy",
            "status": "NON_PQC_COMPLIANT",
            "reason": "SSL Policy allows legacy TLS 1.1.",
            "severity": "HIGH"
        }
    ]

# Summary statistics metrics
total_assets = len(findings)
compliant_count = sum(1 for f in findings if f["status"] == "PQC_COMPLIANT")
critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
pqc_ready_percentage = int((compliant_count / total_assets) * 100) if total_assets > 0 else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Inspected Assets", total_assets)
col2.metric("PQC Compliant Assets", compliant_count)
col3.metric("Critical Security Risks", critical_count)
col4.metric("Overall PQC Readiness", f"{pqc_ready_percentage}%")

st.write("---")

# Split view for reports
left_col, right_col = st.columns([2, 1])

with left_col:
    st.subheader("📋 Audited Assets & Readiness Log")
    for f in findings:
        status_color = "green" if f["status"] == "PQC_COMPLIANT" else "red"
        st.markdown(f"**Resource:** `{f['resource']}`")
        st.markdown(f"- **Type:** `{f['type']}`")
        st.markdown(f"- **Readiness Status:** :{status_color}[{f['status']}] (Severity: **{f['severity']}**)")
        st.markdown(f"- **Detail**: {f['reason']}")
        st.write("")

with right_col:
    st.subheader("💡 Shor Algorithm Qubit Estimator Calculator")
    st.write("Calculate quantum computing requirements to crack classical algorithms.")
    bit_depth = st.number_input("Classical Key Bit Depth", min_value=256, max_value=8192, value=2048, step=256)
    
    # Calculate estimates
    logical_qubits = 2 * bit_depth + 2
    gate_depth = int(bit_depth ** 3)
    
    st.write(f"**Logical Qubits Required:** {logical_qubits:,}")
    st.write(f"**T-Gate Execution Depth:** ~{gate_depth:,}")
    
    st.info("Harvest Now, Decrypt Later (HNDL) protection recommends migrating immediately if keys have long shelf-lives.")
