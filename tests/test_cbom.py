from scanners.gcp_pqc_inventory_scanner import generate_cbom

def test_generate_cbom_minimal():
    findings = [
        {
            "resource_name": "//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/r/cryptoKeys/k1",
            "resource_type": "kms.CryptoKey",
            "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
            "status": "NON_PQC_COMPLIANT",
            "severity": "CRITICAL",
            "recommendation": "Rotate to hybrid",
            "hndl_priority": "IMMEDIATE",
            "raw_metadata": {}
        }
    ]

    cbom = generate_cbom(findings)
    assert cbom.get("bomFormat") == "CycloneDX"
    assert isinstance(cbom.get("components"), list)
    assert cbom["components"][0]["type"] == "cryptographic-asset"
    # ensure custom property was set
    props = cbom["components"][0].get("properties", [])
    assert any(p["name"].startswith("pqc:") for p in props)
