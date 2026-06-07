# Contributing to gcp-pqc-migration-toolkit

Thank you for contributing to our Post-Quantum Cryptography Migration Toolkit.

## Cryptographic Guidelines
- All modifications to key encapsulation (KEM) simulation or digital signature modeling must strictly reference current NIST FIPS 203/204/205 drafts.
- Do not introduce custom, unverified cryptographic implementations. Use standard library or validated vendor APIs.

## Code Quality Standards
- Write Python code matching PEP 8 specifications.
- Use explicit type hints for all public functions.
- Run tests before submitting a Pull Request:
  ```bash
  python -m pytest tests/
  ```

## Pull Request Process
1. Fork the repository and create your branch from `main`.
2. Update unit tests to verify any new logic.
3. Ensure CI validations pass successfully.
