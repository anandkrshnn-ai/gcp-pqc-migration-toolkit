import os
import sys
import json
import csv
import argparse

# Expanded Simulated GCP Asset Inventory data representing Cert Manager & GKE elements
DEFAULT_MOCK_ASSETS = [
    {
        "name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-rsa",
        "type": "kms.CryptoKey",
        "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
        "status": "NON_PQC_COMPLIANT",
        "severity": "CRITICAL"
    },
    {
        "name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/pqc-wrapped-hybrid",
        "type": "kms.CryptoKey",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "status": "PQC_COMPLIANT",
        "severity": "NONE"
    },
    {
        "name": "//compute.googleapis.com/projects/pqc-demo-project/global/sslPolicies/legacy-tls-policy",
        "type": "compute.SslPolicy",
        "minTlsVersion": "TLS_1_1",
        "status": "NON_PQC_COMPLIANT",
        "severity": "HIGH"
    },
    {
        "name": "//certificatemanager.googleapis.com/projects/pqc-demo-project/locations/global/certificates/legacy-rsa-cert",
        "type": "certificatemanager.Certificate",
        "keyAlgorithm": "RSA_2048",
        "status": "NON_PQC_COMPLIANT",
        "severity": "CRITICAL"
    },
    {
        "name": "//binaryauthorization.googleapis.com/projects/pqc-demo-project/policy",
        "type": "binaryauthorization.Policy",
        "signatureAlgorithm": "ECDSA_P256_SHA256",
        "status": "NON_PQC_COMPLIANT",
        "severity": "HIGH"
    }
]

def load_assets(file_path=None, max_log_lines=500):
    """Loads assets from a path if specified and safe, else falls back to mock assets."""
    if not file_path:
        return DEFAULT_MOCK_ASSETS

    abs_path = os.path.abspath(file_path)
    # Directory traversal prevention
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not abs_path.startswith(project_root):
        print(f"[Warning] Blocked path traversal attempt to: {file_path}", file=sys.stderr)
        return DEFAULT_MOCK_ASSETS

    if not os.path.exists(abs_path):
        print(f"[Warning] Asset file not found: {file_path}. Using mock data.", file=sys.stderr)
        return DEFAULT_MOCK_ASSETS

    try:
        log_lines = []
        truncated = False
        with open(abs_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= max_log_lines:
                    truncated = True
                    break
                log_lines.append(line.rstrip('\n'))
                
        if truncated:
            print(f"[Warning] Input log truncated to {max_log_lines} lines.", file=sys.stderr)
            
        return json.loads("\n".join(log_lines))
    except Exception as e:
        print(f"[Warning] Failed to load JSON from {file_path}: {e}. Falling back to mock data.", file=sys.stderr)
        return DEFAULT_MOCK_ASSETS

def scan_inventory(assets):
    """Evaluates assets against PQC cryptographic migration standards."""
    findings = []
    for asset in assets:
        finding = {
            "resource": asset.get("name"),
            "type": asset.get("type"),
            "status": "PQC_COMPLIANT",
            "reason": "Meets post-quantum requirements or hybrid wrapping models.",
            "severity": "NONE"
        }
        
        # Check KMS Algorithms
        if asset.get("type") == "kms.CryptoKey":
            algo = asset.get("algorithm", "")
            if "RSA" in algo or "EC_" in algo:
                finding["status"] = "NON_PQC_COMPLIANT"
                finding["reason"] = f"Uses legacy algorithm: {algo}. Vulnerable to quantum decrypt."
                finding["severity"] = asset.get("severity", "HIGH")
                
        # Check TLS profiles
        elif asset.get("type") == "compute.SslPolicy":
            tls_ver = asset.get("minTlsVersion", "")
            if tls_ver in ["TLS_1_0", "TLS_1_1", "TLS_1_2"]:
                finding["status"] = "NON_PQC_COMPLIANT"
                finding["reason"] = f"SSL Policy allows legacy {tls_ver}. TLS 1.3 is required for quantum resistance."
                finding["severity"] = asset.get("severity", "HIGH")

        # Check Certificate Manager Keys
        elif asset.get("type") == "certificatemanager.Certificate":
            key_algo = asset.get("keyAlgorithm", "")
            if "RSA" in key_algo or "ECDSA" in key_algo:
                finding["status"] = "NON_PQC_COMPLIANT"
                finding["reason"] = f"Certificate relies on classical asymmetric signature: {key_algo}."
                finding["severity"] = "CRITICAL"

        # Check GKE Binary Authorization Gates
        elif asset.get("type") == "binaryauthorization.Policy":
            sig_algo = asset.get("signatureAlgorithm", "")
            if "ML_DSA" not in sig_algo:
                finding["status"] = "NON_PQC_COMPLIANT"
                finding["reason"] = f"GKE Binary Authorization allows non-PQC algorithm: {sig_algo}. ML-DSA-65/85 required."
                finding["severity"] = "HIGH"

        findings.append(finding)
    return findings

def export_to_csv(findings, output_csv_path):
    """Simulates BigQuery export by saving findings to a structured CSV file."""
    try:
        with open(output_csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Resource", "Type", "Status", "Reason", "Severity"])
            for finding in findings:
                writer.writerow([
                    finding["resource"],
                    finding["type"],
                    finding["status"],
                    finding["reason"],
                    finding["severity"]
                ])
        print(f"BigQuery export simulation saved to CSV: {output_csv_path}")
    except Exception as e:
        print(f"[Error] Failed to write CSV report: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="GCP Post-Quantum Compliance Assessor")
    parser.add_argument("--file", help="Optional path to a custom structured GCP asset log.")
    parser.add_argument("--max-log-lines", type=int, default=500, help="Maximum lines to load from files.")
    parser.add_argument("--bq-export-sim", default="pqc_inventory_export.csv", help="Simulate BigQuery export output CSV path.")
    args = parser.parse_args()

    assets = load_assets(args.file, max_log_lines=args.max_log_lines)
    findings = scan_inventory(assets)

    # Print results to stdout as formatted markdown table
    print("\n### GCP Post-Quantum Cryptography Compliance Report")
    print("-" * 120)
    print(f"{'Resource name':<75} | {'Compliance Status':<20} | {'Severity':<10}")
    print("-" * 120)
    for f in findings:
        print(f"{f['resource'][-75:]:<75} | {f['status']:<20} | {f['severity']:<10}")
    print("-" * 120)

    # Save output structured report
    with open("pqc_compliance_report.json", "w", encoding="utf-8") as out:
        json.dump(findings, out, indent=2)
    print("Report saved to: pqc_compliance_report.json")

    # Run BigQuery CSV export simulation
    if args.bq_export_sim:
        export_to_csv(findings, args.bq_export_sim)

if __name__ == "__main__":
    main()
