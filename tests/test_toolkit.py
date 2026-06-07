import os
import sys
import pytest

# Add scanners and simulation folders to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'simulation')))

from gcp_pqc_inventory_scanner import load_assets, scan_inventory
from cirq_quantum_estimator import estimate_shors_requirements, simulate_toy_quantum_step

def test_pqc_scanner_compliance_mapping():
    # Setup test assets with mix of compliant and non-compliant ciphers
    test_assets = [
        {
            "name": "kms/key-1",
            "type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN_PKCS1_2048_SHA256"
        },
        {
            "name": "kms/key-2",
            "type": "kms.CryptoKey",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
        }
    ]
    findings = scan_inventory(test_assets)
    assert len(findings) == 2
    assert findings[0]["status"] == "NON_PQC_COMPLIANT"
    assert findings[1]["status"] == "PQC_COMPLIANT"

def test_shor_requirements_estimation():
    # Verify exact math formulas for qubit/gate scaling
    bits = 2048
    qubits, depth = estimate_shors_requirements(bits)
    assert qubits == 2 * bits + 2
    assert depth == bits ** 3

def test_toy_cirq_simulation_run():
    # Verify Cirq circuit runs successfully without memory locks
    sim_output = simulate_toy_quantum_step()
    assert "result" in sim_output

def test_path_traversal_prevention(capsys):
    # Verify relative paths outside root are blocked and fallback occurs
    malicious_path = "../../../etc/passwd"
    assets = load_assets(malicious_path)
    # Should fall back to mock assets
    assert len(assets) > 0
    captured = capsys.readouterr()
    assert "[Warning] Blocked path traversal attempt" in captured.err
