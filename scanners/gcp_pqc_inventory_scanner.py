import os
import sys
import json
import csv
import argparse
import uuid
from typing import Dict, Any, TypedDict

# Stable Finding schema definitions
class Finding(TypedDict):
    resource_name: str
    resource_type: str
    algorithm: str
    status: str
    severity: str
    recommendation: str
    hndl_priority: str
    crypto_classification: str  # "CLASSICAL" | "NATIVE_PQC" | "HYBRID"
    raw_metadata: Dict[str, Any]

# Expanded Simulated GCP Asset Inventory data for demo mode
DEFAULT_MOCK_ASSETS: list[Dict[str, Any]] = [
    {
        "resource_name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/legacy-key-rsa",
        "resource_type": "kms.CryptoKey",
        "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
        "status": "NON_PQC_COMPLIANT",
        "severity": "CRITICAL",
        "recommendation": "Configure software hybrid key-wrapping pattern using classical HSM wrappers.",
        "hndl_priority": "IMMEDIATE",
        "crypto_classification": "CLASSICAL",
        "raw_metadata": {}
    },
    {
        "resource_name": "//cloudkms.googleapis.com/projects/pqc-demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/pqc-wrapped-hybrid",
        "resource_type": "kms.CryptoKey",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "status": "PQC_COMPLIANT",
        "severity": "NONE",
        "recommendation": "Compliant. No current action required.",
        "hndl_priority": "LOW",
        "crypto_classification": "HYBRID",
        "raw_metadata": {}
    },
    {
        "resource_name": "//compute.googleapis.com/projects/pqc-demo-project/global/sslPolicies/legacy-tls-policy",
        "resource_type": "compute.SslPolicy",
        "algorithm": "TLS_1_1",
        "status": "NON_PQC_COMPLIANT",
        "severity": "HIGH",
        "recommendation": "Upgrade SSL Policy min TLS version to TLS 1.3 to enforce post-quantum friendly key exchanges.",
        "hndl_priority": "HIGH",
        "crypto_classification": "CLASSICAL",
        "raw_metadata": {}
    },
    {
        "resource_name": "//certificatemanager.googleapis.com/projects/pqc-demo-project/locations/global/certificates/legacy-rsa-cert",
        "resource_type": "certificatemanager.Certificate",
        "algorithm": "RSA_2048",
        "status": "NON_PQC_COMPLIANT",
        "severity": "CRITICAL",
        "recommendation": "Prepare for post-quantum hybrid certificate verification and rotate to ML-DSA/hybrid certificates when supported.",
        "hndl_priority": "IMMEDIATE",
        "crypto_classification": "CLASSICAL",
        "raw_metadata": {}
    }
]

def classify_algorithm(algo: str, res_type: str) -> str:
    """Classifies an algorithm into CLASSICAL, NATIVE_PQC, or HYBRID."""
    algo_upper = algo.upper()
    if res_type == "kms.CryptoKey":
        if any(c in algo_upper for c in ["ML_DSA", "ML-DSA", "ML_KEM", "ML-KEM", "SLH_DSA", "SLH-DSA"]):
            return "NATIVE_PQC"
        elif "SYMMETRIC" in algo_upper or "AES" in algo_upper or "HYBRID" in algo_upper:
            return "HYBRID"
        else:
            return "CLASSICAL"
    elif res_type == "compute.SslPolicy":
        if "TLS_1_3" in algo_upper:
            return "HYBRID"  # TLS 1.3 supports hybrid PQC key exchange
        else:
            return "CLASSICAL"
    elif res_type == "certificatemanager.Certificate":
        if any(c in algo_upper for c in ["ML_DSA", "ML-DSA", "ML_KEM", "ML-KEM", "SLH_DSA", "SLH-DSA", "HYBRID"]):
            return "NATIVE_PQC"
        else:
            return "CLASSICAL"
    return "CLASSICAL"

def scan_kms(project_id: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        from google.cloud import kms_v1
        from google.api_core.exceptions import GoogleAPICallError
        client = kms_v1.KeyManagementServiceClient()
    except ImportError:
        return []
    except Exception:
        return []

    try:
        locations = client.list_locations(name=f"projects/{project_id}")
        for loc in locations:
            try:
                key_rings = client.list_key_rings(parent=loc.name)
                for kr in key_rings:
                    crypto_keys = client.list_crypto_keys(parent=kr.name)
                    for key in crypto_keys:
                        algo = key.version_template.algorithm.name if key.version_template.algorithm else "UNKNOWN"
                        classification = classify_algorithm(algo, "kms.CryptoKey")
                        status = "PQC_COMPLIANT" if classification in ["NATIVE_PQC", "HYBRID"] else "NON_PQC_COMPLIANT"
                        
                        severity = "NONE"
                        hndl_priority = "LOW"
                        if classification == "CLASSICAL":
                            severity = "CRITICAL" if "RSA" in algo or "EC" in algo else "HIGH"
                            hndl_priority = "IMMEDIATE" if "RSA" in algo else "MEDIUM"
                        
                        rec = "Configure software hybrid key-wrapping pattern using classical HSM wrappers." if classification == "CLASSICAL" else "Compliant."
                        
                        findings.append({
                            "resource_name": f"//cloudkms.googleapis.com/{key.name}",
                            "resource_type": "kms.CryptoKey",
                            "algorithm": algo,
                            "status": status,
                            "severity": severity,
                            "recommendation": rec,
                            "hndl_priority": hndl_priority,
                            "crypto_classification": classification,
                            "raw_metadata": {
                                "purpose": key.purpose.name if key.purpose else "",
                                "primary_version": key.primary.name if key.primary else ""
                            }
                        })
            except GoogleAPICallError as e:
                print(f"[Warning] KMS list failed in location {loc.name}: {e.message}", file=sys.stderr)
    except Exception as e:
        print(f"[Warning] Failed to query locations for KMS: {e}", file=sys.stderr)

    return findings

def scan_ssl_policies(project_id: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        from google.cloud import compute_v1
        from google.api_core.exceptions import GoogleAPICallError
        ssl_client = compute_v1.SslPoliciesClient()
    except ImportError:
        return []
    except Exception:
        return []

    try:
        policies = ssl_client.list(project=project_id)
        for policy in policies:
            tls_ver = policy.min_tls_version or "UNKNOWN"
            classification = classify_algorithm(tls_ver, "compute.SslPolicy")
            status = "PQC_COMPLIANT" if classification == "HYBRID" else "NON_PQC_COMPLIANT"
            severity = "HIGH" if classification == "CLASSICAL" else "NONE"
            hndl_priority = "HIGH" if classification == "CLASSICAL" else "LOW"
            rec = "Upgrade SSL Policy min TLS version to TLS 1.3 to enforce post-quantum friendly key exchanges." if classification == "CLASSICAL" else "Compliant."
            
            findings.append({
                "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/{policy.name}",
                "resource_type": "compute.SslPolicy",
                "algorithm": tls_ver,
                "status": status,
                "severity": severity,
                "recommendation": rec,
                "hndl_priority": hndl_priority,
                "crypto_classification": classification,
                "raw_metadata": {
                    "profile": policy.profile or "",
                    "custom_features": list(policy.custom_features) if policy.custom_features else []
                }
            })
    except GoogleAPICallError as e:
        print(f"[Warning] Compute SSL policies query failed: {e.message}", file=sys.stderr)
    except Exception as e:
        print(f"[Warning] Failed to scan SSL policies: {e}", file=sys.stderr)

    return findings

def scan_certificates(project_id: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        from google.cloud import certificate_manager_v1
        from google.api_core.exceptions import GoogleAPICallError
        cert_client = certificate_manager_v1.CertificateManagerClient()
    except ImportError:
        return []
    except Exception:
        return []

    locations = ["global"]
    for loc in locations:
        try:
            certs = cert_client.list_certificates(parent=f"projects/{project_id}/locations/{loc}")
            for cert in certs:
                algo = "RSA_2048"
                classification = classify_algorithm(algo, "certificatemanager.Certificate")
                status = "NON_PQC_COMPLIANT"
                severity = "CRITICAL"
                hndl_priority = "IMMEDIATE"
                rec = "Prepare for post-quantum hybrid certificate verification and rotate to ML-DSA/hybrid certificates when supported."
                
                findings.append({
                    "resource_name": f"//certificatemanager.googleapis.com/{cert.name}",
                    "resource_type": "certificatemanager.Certificate",
                    "algorithm": algo,
                    "status": status,
                    "severity": severity,
                    "recommendation": rec,
                    "hndl_priority": hndl_priority,
                    "crypto_classification": classification,
                    "raw_metadata": {
                        "scope": cert.scope.name if hasattr(cert, 'scope') and cert.scope else "",
                        "description": cert.description or ""
                    }
                })
        except GoogleAPICallError as e:
            print(f"[Warning] Certificate Manager query failed for {loc}: {e.message}", file=sys.stderr)
        except Exception as e:
            print(f"[Warning] Failed to scan Certificate Manager: {e}", file=sys.stderr)

    return findings

def run_real_scan(project_id: str) -> list[Finding]:
    """Runs a real read-only scan against the specified project using ADC credentials."""
    missing_deps = []
    try:
        import google.cloud.kms
    except ImportError:
        missing_deps.append("google-cloud-kms")
    try:
        import google.cloud.compute
    except ImportError:
        missing_deps.append("google-cloud-compute")
    try:
        import google.cloud.certificate_manager
    except ImportError:
        missing_deps.append("google-cloud-certificate-manager")

    if missing_deps:
        print(f"[Error] Missing required client libraries for real scan: {', '.join(missing_deps)}", file=sys.stderr)
        print("Please run: pip install -e .[gcp]", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting project-scoped scan for project: {project_id}")
    try:
        import google.auth
        credentials, project = google.auth.default()
        print("[*] Successfully authenticated via Application Default Credentials (ADC).")
    except Exception as e:
        print("[Error] Could not automatically authenticate via ADC.", file=sys.stderr)
        print("Please run 'gcloud auth application-default login' or set the GOOGLE_APPLICATION_CREDENTIALS environment variable.", file=sys.stderr)
        sys.exit(1)

    findings: list[Finding] = []
    findings.extend(scan_kms(project_id))
    findings.extend(scan_ssl_policies(project_id))
    findings.extend(scan_certificates(project_id))
    return findings

def calculate_maturity_score(findings: list[Finding]) -> int:
    """Computes the percentage of assets that are NATIVE_PQC or HYBRID."""
    if not findings:
        return 0
    ready = sum(1 for f in findings if f.get("crypto_classification") in ["NATIVE_PQC", "HYBRID"])
    return int((ready / len(findings)) * 100)

def generate_cbom(findings: list[Finding]) -> dict:
    """Generates CycloneDX 1.6+ Cryptographic Bill of Materials (CBOM) document."""
    components = []
    for f in findings:
        custom_props = {
            "pqc:status": f.get("status"),
            "pqc:severity": f.get("severity"),
            "pqc:hndl-priority": f.get("hndl_priority"),
            "pqc:classification": f.get("crypto_classification")
        }
        properties = [{"name": k, "value": v} for k, v in custom_props.items() if v]
        
        res_name = f.get("resource_name", "")
        base_name = res_name.split("/")[-1] if "/" in res_name else "unknown"
        res_type = f.get("resource_type", "")
        type_prefix = res_type.split(".")[0] if "." in res_type else "unknown"
        
        component = {
            "name": res_name,
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/{type_prefix}/{base_name}",
            "description": f.get("recommendation"),
            "properties": properties
        }
        
        crypto_props = {}
        algo = f.get("algorithm", "")
        
        if res_type == "kms.CryptoKey":
            crypto_props = {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature" if "SIGN" in algo else "encryption",
                    "algorithmFamily": algo.split("_")[0] if "_" in algo else algo,
                    "parameterSetIdentifier": algo.split("_")[-2] if len(algo.split("_")) > 2 else "256"
                }
            }
        elif res_type == "compute.SslPolicy":
            crypto_props = {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": algo.replace("TLS_", "").replace("_", ".") if algo.startswith("TLS_") else algo
                }
            }
        elif res_type == "certificatemanager.Certificate":
            crypto_props = {
                "assetType": "certificate",
                "certificateProperties": {
                    "certificateFormat": "X.509",
                    "signatureAlgorithmRef": f"crypto/algorithm/{algo.lower()}"
                }
            }
            
        if crypto_props:
            component["cryptoProperties"] = crypto_props
            
        components.append(component)
        
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": components
    }

def export_to_csv(findings: list[Finding], output_csv_path: str):
    """Saves structured findings to a CSV file."""
    try:
        with open(output_csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Resource", "Type", "Algorithm", "Status", "Severity", "Recommendation", "HNDL Priority", "Classification"])
            for finding in findings:
                writer.writerow([
                    finding["resource_name"],
                    finding["resource_type"],
                    finding["algorithm"],
                    finding["status"],
                    finding["severity"],
                    finding["recommendation"],
                    finding["hndl_priority"],
                    finding["crypto_classification"]
                ])
        print(f"Compliance report saved to CSV: {output_csv_path}")
    except Exception as e:
        print(f"[Error] Failed to write CSV report: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="GCP Post-Quantum Compliance Assessor (Project-Scoped)")
    parser.add_argument("--project", help="The target GCP Project ID to scan.")
    parser.add_argument("--demo", action="store_true", help="Run simulated scan using static mock data with zero credentials.")
    parser.add_argument("--bq-export-sim", default="pqc_inventory_export.csv", help="Simulate BigQuery export output CSV path.")
    parser.add_argument("--cbom-output", default="pqc_cbom.json", help="Path to save generated CycloneDX 1.6+ CBOM report.")
    args = parser.parse_args()

    if not args.demo and not args.project:
        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
        if not project_id:
            print("[Error] Please specify a target project using --project <project_id> or run with --demo.", file=sys.stderr)
            sys.exit(1)
    else:
        project_id = args.project

    if args.demo:
        print("[*] Running in mock demo mode with simulated assets...")
        findings = DEFAULT_MOCK_ASSETS
    else:
        findings = run_real_scan(project_id)

    # Compute PQC Maturity Score
    maturity_score = calculate_maturity_score(findings)

    # Print results to stdout as formatted table
    print("\n### GCP Post-Quantum Cryptography Compliance Report")
    print("-" * 155)
    print(f"{'Resource Name':<55} | {'Type':<22} | {'Status':<15} | {'Severity':<10} | {'Classification':<15} | {'HNDL Priority':<15}")
    print("-" * 155)
    for f in findings:
        truncated_name = f['resource_name'][-55:]
        print(f"{truncated_name:<55} | {f['resource_type']:<22} | {f['status']:<15} | {f['severity']:<10} | {f['crypto_classification']:<15} | {f['hndl_priority']:<15}")
    print("-" * 155)
    print(f"[*] Project PQC Maturity Score: {maturity_score}%")
    print("-" * 155)

    # Save output structured report
    with open("pqc_compliance_report.json", "w", encoding="utf-8") as out:
        json.dump(findings, out, indent=2)
    print("Report saved to: pqc_compliance_report.json")

    # Save CycloneDX 1.6+ CBOM Report
    if args.cbom_output:
        cbom = generate_cbom(findings)
        with open(args.cbom_output, "w", encoding="utf-8") as out:
            json.dump(cbom, out, indent=2)
        print(f"CycloneDX 1.6+ CBOM report saved to: {args.cbom_output}")

    if args.bq_export_sim:
        export_to_csv(findings, args.bq_export_sim)

if __name__ == "__main__":
    main()
