import os
import sys
import pytest

# Add scanners and simulation folders to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'simulation')))

from gcp_pqc_inventory_scanner import load_assets, scan_inventory, export_to_csv
from cirq_quantum_estimator import estimate_shors_requirements, simulate_toy_quantum_step

def test_pqc_scanner_compliance_mapping():
    # Test assets with Certificates and GKE Binary Authorization Policies
    test_assets = [
        {
            "name": "kms/key-1",
            "type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN_PKCS1_2048_SHA256"
        },
        {
            "name": "certs/cert-1",
            "type": "certificatemanager.Certificate",
            "keyAlgorithm": "RSA_2048"
        },
        {
            "name": "binauth/policy-1",
            "type": "binaryauthorization.Policy",
            "signatureAlgorithm": "ECDSA_P256_SHA256"
        }
    ]
    findings = scan_inventory(test_assets)
    assert len(findings) == 3
    assert findings[0]["status"] == "NON_PQC_COMPLIANT"
    assert findings[0]["severity"] == "HIGH"
    
    assert findings[1]["status"] == "NON_PQC_COMPLIANT"
    assert findings[1]["severity"] == "CRITICAL"

    assert findings[2]["status"] == "NON_PQC_COMPLIANT"
    assert findings[2]["severity"] == "HIGH"

def test_csv_export_simulation():
    findings = [
        {
            "resource": "kms/key-1",
            "type": "kms.CryptoKey",
            "status": "NON_PQC_COMPLIANT",
            "reason": "Uses legacy algorithm",
            "severity": "HIGH"
        }
    ]
    csv_file = "test_export.csv"
    try:
        export_to_csv(findings, csv_file)
        assert os.path.exists(csv_file)
    finally:
        if os.path.exists(csv_file):
            os.remove(csv_file)

def test_shor_requirements_estimation():
    bits = 2048
    qubits, depth = estimate_shors_requirements(bits)
    assert qubits == 2 * bits + 2
    assert depth == bits ** 3

def test_toy_cirq_simulation_run():
    sim_output = simulate_toy_quantum_step()
    assert "result" in sim_output

def test_path_traversal_prevention(capsys):
    malicious_path = "../../../etc/passwd"
    assets = load_assets(malicious_path)
    assert len(assets) > 0
    captured = capsys.readouterr()
    assert "[Warning] Blocked path traversal attempt" in captured.err
