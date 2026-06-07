# Release Notes - v1.0.0 (GCP PQC Migration Assessment Toolkit)

We are proud to release **v1.0.0** of the **GCP Post-Quantum Cryptography (PQC) Migration Assessment Toolkit**! 

This release establishes the first open-source discovery, risk quantification, and readiness planning framework built specifically for Google Cloud Platform (GCP) environments to address the upcoming post-quantum transition.

## Toolkit Scope & Reframing
To maintain absolute engineering transparency, **v1.0.0 is focused purely on Discovery, Assessment, and Planning**. Because Google Cloud KMS HSM modules do not yet natively support post-quantum algorithms (ML-KEM/ML-DSA) at hardware levels, this toolkit does *not* execute automated algorithmic remediation. Instead, it provides the audit rails, risk calculators, and policy blueprints needed to discover classical vulnerabilities and plan transition enclaves.

---

## Key Features in v1.0.0

### 🛡️ PQC Asset & Discovery Scanner (`scanners/`)
- Automated scanning of GCP KMS key algorithms, SSL/TLS policies, GKE Binary Authorization, and custom domain certificates.
- Identifies critical exposure to **Harvest Now, Decrypt Later (HNDL)** attacks by auditing legacy ciphers (RSA, ECDSA).
- Outputs standardized PQC compliance audit logs to JSON and simulated BigQuery exports in CSV format (`pqc_inventory_export.csv`).

### 🔬 Shor's Algorithm Resource Estimator (`simulation/`)
- Estimator built on `cirq` that calculates classical-quantum bit depth requirements.
- Computes logical qubit requirements and approximate T-gate depth for cryptographic key lengths (e.g. RSA-2048, ECC-256, RSA-4096).
- Simulates toy 3-qubit phase estimation registers to illustrate quantum algorithm execution steps.

### 📊 Streamlit Compliance Dashboard (`dashboard/`)
- Interactive interface illustrating organizational PQC readiness percentages.
- Features Shor estimation controls and HNDL breach threat timeline forecasts.
- Integrates a 5-year migration milestones visualizer.

### ⚙️ Modular Terraform IaC Policy Blueprints (`terraform/`)
- **`modules/pqc-kms`**: Provisions HSM-backed Cloud KMS keyrings configured for hybrid wrapping models.
- **`modules/pqc-policies`**: Blueprints for organization policies enforcing load balancer TLS versions and cipher suites.
- **`examples/banking-demo`**: Complete, multi-region bank IaC template demonstrating how to deploy PQC controls at scale.

### 🧪 Automated Verification Suite (`tests/`)
- Comprehensive test coverage using `pytest` ensuring:
  - Cryptographic scanner logic correctness.
  - Shor scaling estimation accuracy.
  - Path traversal and directory escape validation.

---

## Technical Specifications & Limitations

For detailed operational constraints, see [limitations.md](docs/limitations.md).
- **KMS Limitations**: Google Cloud KMS HSM modules do not currently support FIPS 203 (ML-KEM) at the hardware level. Current hybrid configurations use a software-based PQC wrapping envelope (such as Confidential Space).
- **Packet Fragmentation**: Larger signature sizes for ML-DSA (FIPS 204) can trigger MTU packet fragmentation across standard WAN networks, necessitating MTU adjustments.
