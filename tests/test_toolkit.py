import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Add scanners and simulation folders to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'simulation')))

from gcp_pqc_inventory_scanner import DEFAULT_MOCK_ASSETS, export_to_csv
from cirq_quantum_estimator import estimate_shors_requirements, simulate_toy_quantum_step, get_hndl_priority

def test_pqc_findings_schema_compliance():
    # Verify mock assets match the stable Finding schema
    for asset in DEFAULT_MOCK_ASSETS:
        assert "resource_name" in asset
        assert "resource_type" in asset
        assert "algorithm" in asset
        assert "status" in asset
        assert "severity" in asset
        assert "recommendation" in asset
        assert "hndl_priority" in asset
        assert "raw_metadata" in asset
        assert asset["status"] in ["PQC_COMPLIANT", "NON_PQC_COMPLIANT"]
        assert asset["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

def test_csv_export_format():
    test_findings = [
        {
            "resource_name": "//cloudkms.googleapis.com/projects/test/locations/us-central1/keyRings/r/cryptoKeys/k",
            "resource_type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN",
            "status": "NON_PQC_COMPLIANT",
            "severity": "CRITICAL",
            "recommendation": "Migrate",
            "hndl_priority": "IMMEDIATE"
        }
    ]
    csv_file = "test_export_schema.csv"
    try:
        export_to_csv(test_findings, csv_file)
        assert os.path.exists(csv_file)
    finally:
        if os.path.exists(csv_file):
            os.remove(csv_file)

def test_estimator_literature_math():
    # Test RSA scaling
    rsa_bits = 2048
    logical, physical, depth = estimate_shors_requirements(rsa_bits, is_ecc=False)
    assert logical == 2 * rsa_bits + 2
    assert physical == logical * 4900
    assert depth == rsa_bits ** 3

    # Test ECC scaling
    ecc_bits = 256
    logical_ecc, physical_ecc, depth_ecc = estimate_shors_requirements(ecc_bits, is_ecc=True)
    assert logical_ecc == int(6 * ecc_bits)
    assert physical_ecc == logical_ecc * 4000
    assert depth_ecc == int(0.5 * (ecc_bits ** 3))

def test_hndl_priority_levels():
    priority, level = get_hndl_priority(12)
    assert level == "CRITICAL"
    assert "IMMEDIATE" in priority

    priority, level = get_hndl_priority(6)
    assert level == "HIGH"
    
    priority, level = get_hndl_priority(1)
    assert level == "LOW"

def test_toy_quantum_simulation_step():
    sim_output = simulate_toy_quantum_step()
    # It will output the measurement result string or a skip message if cirq is missing
    assert isinstance(sim_output, str)

@patch("google.auth.default")
def test_real_scan_authentication_failure(mock_auth):
    # Simulate authentication failure
    mock_auth.side_effect = Exception("No credentials found")
    from gcp_pqc_inventory_scanner import run_real_scan
    with pytest.raises(SystemExit):
        run_real_scan("invalid-project")
