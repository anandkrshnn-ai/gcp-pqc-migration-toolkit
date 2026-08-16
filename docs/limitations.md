# Known Operational Limitations & Architectural Constraints

This document outlines the real operational boundaries and constraints when migrating to Post-Quantum Cryptography (PQC) on GCP.

---

## 1. Cloud KMS Native Limitations
- **No Native Hardware PQC Support**: As of mid-2026, Google Cloud KMS HSM modules do not natively support NIST PQC algorithms (e.g., ML-KEM, ML-DSA) for hardware-bound cryptographic operations.
- **Software Workarounds (Enclaves)**: To use post-quantum key encapsulation or signing keys today, applications must manage raw PQC key materials within secure environments (such as Confidential Space/Confidential VMs) or software wrapper services. 
- **Classical Wrapping (Hybrid Model)**: A common approach is using Cloud KMS classical keys (e.g., AES-256 or RSA-4096) as a Key Encryption Key (KEK) to wrap software-defined PQC private keys. This establishes crypto-agility but introduces operational complexity, as key management and raw cryptographic operations are split between KMS and the client application.

## 2. Signature and Key Size Overhead
- **Network Latency & Storage Growth**: NIST PQC keys and signatures are significantly larger than classical counterparts:
  - **RSA-2048**: Public Key = 256 bytes, Signature = 256 bytes.
  - **ML-KEM-768**: Public Key = 1,184 bytes, Ciphertext = 1,088 bytes.
  - **ML-DSA-65**: Public Key = 1,952 bytes, Signature = 3,300 bytes.
- **Impact**: Large signature sizes can lead to MTU fragmentation, increased network egress costs, and storage expansion in audit/transaction logs.

## 3. Estimator Simulation Thresholds
- **Simulation Memory Bounds**: Classical computers cannot simulate large quantum computers. Quantum simulation of Shor's algorithm via Cirq is limited to toy systems (e.g., under 30 qubits). For real-world keys (e.g., RSA-2048), the estimator uses mathematical scaling models based on physical qubit and gate-depth requirements derived from peer-reviewed literature.
