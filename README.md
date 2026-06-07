# GCP Post-Quantum Cryptography (PQC) Migration Toolkit

[![CI Pipeline](https://github.com/anandkrshnn/gcp-pqc-migration-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/anandkrshnn/gcp-pqc-migration-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A production-quality toolkit helping enterprise security teams migrate from legacy classical cryptography (RSA/ECC) to NIST-standardized Post-Quantum Cryptography (PQC) on Google Cloud. Focuses on **Harvest Now, Decrypt Later (HNDL)** risk mitigations, crypto-agility audits, and transition orchestration.

---

## 1. Architecture Overview

The migration lifecycle follows a four-stage process automated by this toolkit:

```mermaid
graph TD
    A[1. Discover & Inventory] --> B[2. Assess Compliance]
    B --> C[3. Configure Hybrid Enclaves]
    C --> D[4. Enforce PQC Policies]
    
    subgraph scanners/
        A -->|Scan KMS, TLS, IAM| Scanner[gcp_pqc_inventory_scanner.py]
    end
    
    subgraph simulation/
        Scanner -->|HNDL Estimator| Estimator[cirq_quantum_estimator.py]
    end
    
    subgraph terraform/
        Estimator -->|Deploy KMS Hybrid Keys| KMSModule[modules/pqc-kms]
        Estimator -->|Enforce Org Policies| PolicyModule[modules/pqc-policies]
    end
    
    subgraph dashboard/
        KMSModule -->|Track Metrics| Dashboard[streamlit_compliance_dashboard.py]
    end
```

---

## 2. Core Features

- **PQC Inventory Scanner**: Evaluates GCP environments for algorithm compliance, flagging legacy SSL policies, non-hybrid Cloud KMS structures, and missing VPC Service Controls.
- **Shor Qubit Estimator**: Implements a physical qubit and gate-depth requirement estimator using `cirq` to trace when Shor's algorithm can crack active RSA/ECC assets based on simulated quantum hardware scaling.
- **IaC Hybrid Wrappers**: Terraform modules to provision Cloud KMS keyring enclaves and GCP Org Policies restricting classical cipher usage.
- **Compliance Dashboard**: Streamlit front-end displaying PQC readiness, HNDL risk indices, and migration milestones.

---

## 3. Governance & Standards Alignment

| Algorithm Standard | NIST Reference | Transition Deadline (GAIP-2030) | Purpose | GCP Migration Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **ML-KEM (FIPS 203)** | Kyber (768/1024) | 2030 (National Security Command) | Key Encapsulation (KEM) | Hybrid HSM-backed Cloud KMS wrapping models |
| **ML-DSA (FIPS 204)** | Dilithium | 2030 | Digital Signatures | GKE binary authorization and IAM validation gates |
| **SLH-DSA (FIPS 205)** | SPHINCS+ | 2033 | State-free Signatures | Root certificate signing and audit logging |

---

## 4. Quickstart Guide

### Prerequisites
- Python 3.10+
- Terraform 1.5+
- Google Cloud SDK (gcloud) authenticated with appropriate permissions.

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/anandkrshnn/gcp-pqc-migration-toolkit.git
   cd gcp-pqc-migration-toolkit
   ```
2. Install Python dependencies:
   ```bash
   pip install -r scanners/requirements.txt
   pip install cirq streamlit
   ```

### 1. Run Inventory Compliance Assessment
Scan a simulated or active GCP target:
```bash
python scanners/gcp_pqc_inventory_scanner.py --max-log-lines 200
```

### 2. Estimate HNDL Quantum Breach Risks
Run the Shor gate-depth estimator for a 2048-bit RSA key:
```bash
python simulation/cirq_quantum_estimator.py --bits 2048
```

### 3. Deploy PQC Dashboard
Start the local Streamlit visual tracking dashboard:
```bash
streamlit run dashboard/streamlit_compliance_dashboard.py
```

---

## 5. Known Operational Limitations
For a detailed breakdown of GCP API limits, Cloud KMS PQC support statuses, and Shor algorithm simulation thresholds, refer to [docs/limitations.md](docs/limitations.md).
