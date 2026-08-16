import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Add scanners and simulation folders to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scanners')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'simulation')))

from gcp_pqc_inventory_scanner import DEFAULT_MOCK_ASSETS, export_to_csv, generate_cbom, calculate_maturity_score
from cirq_quantum_estimator import estimate_shors_requirements, simulate_toy_quantum_step, get_hndl_priority
from report_attester import sign_findings_report
from verify_report import verify_signed_report
from drift_tracker import record_scan, check_for_drift, get_scan_history

def test_cbom_generation():
    cbom = generate_cbom(DEFAULT_MOCK_ASSETS)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert "components" in cbom
    assert len(cbom["components"]) > 0
    for comp in cbom["components"]:
        assert comp["type"] == "cryptographic-asset"
        assert "cryptoProperties" in comp
        assert "assetType" in comp["cryptoProperties"]

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

def test_maturity_score_calculation():
    test_findings = [
        {"crypto_classification": "CLASSICAL"},
        {"crypto_classification": "NATIVE_PQC"},
        {"crypto_classification": "HYBRID"},
        {"crypto_classification": "CLASSICAL"}
    ]
    # 2 out of 4 are ready -> 50%
    score = calculate_maturity_score(test_findings)
    assert score == 50

def test_report_attestation_success():
    signed_envelope = sign_findings_report(DEFAULT_MOCK_ASSETS)
    assert "payload" in signed_envelope
    assert "signature" in signed_envelope
    assert "publicKey" in signed_envelope
    
    # Verify signature
    is_valid = verify_signed_report(signed_envelope)
    assert is_valid is True

def test_report_attestation_tampering():
    signed_envelope = sign_findings_report(DEFAULT_MOCK_ASSETS)
    # Modify payload data to simulate tampering
    signed_envelope["payload"][0]["recommendation"] = "Tampered recommendation text"
    
    is_valid = verify_signed_report(signed_envelope)
    assert is_valid is False

def test_drift_tracker_recording():
    project_id = "test-drift-project"
    test_findings = [
        {
            "resource_name": "key-1",
            "resource_type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN",
            "status": "NON_PQC_COMPLIANT",
            "severity": "CRITICAL",
            "recommendation": "Migrate",
            "hndl_priority": "IMMEDIATE",
            "crypto_classification": "CLASSICAL"
        }
    ]
    scan_id = record_scan(project_id, test_findings)
    assert isinstance(scan_id, int)
    
    history = get_scan_history(project_id)
    assert len(history) > 0
    assert history[-1]["maturity_score"] == 0

def test_drift_regression_detection():
    project_id = "test-drift-project-reg"
    
    # 1. Base run (Maturity Score = 100%)
    base_findings = [
        {
            "resource_name": "key-1",
            "resource_type": "kms.CryptoKey",
            "algorithm": "ML-DSA-65",
            "status": "PQC_COMPLIANT",
            "severity": "NONE",
            "recommendation": "None",
            "hndl_priority": "LOW",
            "crypto_classification": "NATIVE_PQC"
        }
    ]
    record_scan(project_id, base_findings)
    
    # 2. Second run: downgrade asset back to classical (Maturity Score drops to 0%)
    new_findings = [
        {
            "resource_name": "key-1",
            "resource_type": "kms.CryptoKey",
            "algorithm": "RSA_2048",
            "status": "NON_PQC_COMPLIANT",
            "severity": "CRITICAL",
            "recommendation": "Migrate",
            "hndl_priority": "IMMEDIATE",
            "crypto_classification": "CLASSICAL"
        }
    ]
    
    drift_res = check_for_drift(project_id, new_findings)
    assert drift_res["drift_detected"] is True
    assert drift_res["previous_maturity_score"] == 100
    assert drift_res["new_maturity_score"] == 0
    assert "key-1" in drift_res["downgraded_assets"]


