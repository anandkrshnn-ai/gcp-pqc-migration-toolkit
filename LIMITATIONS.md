# Limitations & Operational Boundaries

This toolkit is designed as an **assessment and planning** aid for post-quantum cryptography (PQC) migration on Google Cloud Platform. It is not a replacement for detailed architectural design, security reviews, or change management processes.

---

## 1. Scope and Coverage

- **Supported Resource Types (Current)**
  - Cloud KMS keys (classification by algorithm family: classical, native PQC, hybrid)
  - TLS-terminating surfaces discoverable via GCP APIs (e.g., HTTPS Load Balancers, Certificate Manager certificates) where metadata is available
  - Project-level aggregation of cryptographic assets for PQC Maturity Score computation

- **Not Yet Covered (or Partially Covered)**
  - In-depth protocol-level analysis (cipher suites, TLS versions, SSH configurations, etc.)
  - Workload-embedded crypto (e.g., keys/certs baked into containers, VMs, or third-party SaaS integrations)
  - Full coverage of all GCP services that may use cryptography internally

---

## 2. Native PQC and Hybrid Support

- The toolkit assumes **native PQC support in GCP** (ML-DSA, ML-KEM, SLH-DSA, and hybrid options such as X-Wing-style configurations) where exposed via APIs and metadata.
- Recommendations are based on **publicly documented GCP capabilities as of 2026**. If your environment uses preview features, custom configurations, or restricted offerings, some recommendations may need manual validation.
- The toolkit does **not** perform cryptographic validation of algorithm implementations; it relies on GCP-reported metadata.

---

## 3. Risk Scoring and Maturity Metrics

- The **PQC Maturity Score** and risk prioritization are **heuristic** and intended for planning, not as formal risk assessments.
- They do not replace:
  - Formal threat modeling
  - Regulatory or auditor determinations
  - Detailed business impact analysis

---

## 4. Compliance and Standards Alignment

- Outputs are aligned conceptually with:
  - NIST PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)
  - Emerging expectations for cryptographic inventories (e.g., NIS2-style requirements, EN 18031 considerations)
- The toolkit does **not** guarantee compliance with any specific regulation or standard. Use the generated reports as **input** to your compliance process, not as definitive evidence.

---

## 5. Operational Considerations

- The toolkit is intended for **periodic scanning and planning**, not real-time enforcement.
- For production use, you should:
  - Run scans in a controlled environment with appropriate IAM permissions
  - Review recommendations with your security and platform teams before applying changes
  - Integrate with your change management and testing processes (especially for cryptographic changes)

---

## 6. Roadmap (Planned Enhancements)

Near-term planned capabilities include:

- **CycloneDX CBOM export** for standardized cryptographic bill-of-materials
- **Attested readiness reports** with tamper-evident, optionally hardware-anchored evidence
- **Continuous drift detection** and readiness score tracking over time
- **Policy-as-code generators** (org policies, Terraform snippets) to enforce PQC posture
- Deeper protocol-level analysis and what-if migration simulations
