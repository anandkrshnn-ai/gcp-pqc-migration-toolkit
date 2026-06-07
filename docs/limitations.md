# Known Operational Limitations & Architectural Constraints

This document outlines the real operational boundaries and constraints when migrating to Post-Quantum Cryptography (PQC) on GCP.

---

## 1. Cloud KMS Native Limitations
- **No Native Hardware PQC Support**: As of June 2026, Google Cloud KMS HSM modules do not natively support NIST PQC algorithms (ML-KEM, ML-DSA) for hardware-bound cryptographic operations.
- **Software Workarounds (Enclaves)**: Enterprises must implement software wrapping layers (e.g., using Confidential Space or HSM classical keys wrapping PQC keys) to achieve hybrid protection. This introduces additional operational overhead and increases trust boundary complexity.

## 2. Signature and Key Size Overhead
- **Network Latency & Storage Growth**: NIST PQC keys and signatures are significantly larger than classical counterparts:
  - **RSA-2048**: Public Key = 256 bytes, Signature = 256 bytes.
  - **ML-KEM-768**: Public Key = 1,184 bytes, Ciphertext = 1,088 bytes.
  - **ML-DSA-65**: Public Key = 1,952 bytes, Signature = 3,300 bytes.
- **Impact**: Large signature sizes can lead to MTU fragmentation, increased network egress costs, and storage expansion in audit/transaction logs.

## 3. Estimator Simulation Thresholds
- **Simulation Memory Bounds**: The Shor qubit estimator simulation (`cirq_quantum_estimator.py`) is classically bounded. Simulating Shor's algorithm for keys larger than 30 bits consumes excessive memory and CPU cycles. The script defaults to mathematical scaling calculations for larger keys to prevent out-of-memory (OOM) crashes.
