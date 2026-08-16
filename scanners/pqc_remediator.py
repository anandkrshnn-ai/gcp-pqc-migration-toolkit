import json
import os
import sys
import argparse

def generate_remediation_plan(findings: list, output_dir: str):
    """Parses compliance findings and outputs remediation manifests and scripts."""
    os.makedirs(output_dir, exist_ok=True)
    
    tf_infra = []
    tf_policies = []
    gcloud_cmds = []
    plan_md = []
    
    # Initialize TF blocks
    tf_infra.append("# Generated Terraform Infrastructures for PQC Compliance Remediation\n")
    tf_policies.append("# Generated Google Cloud Org Policy Constraints to enforce PQC\n")
    gcloud_cmds.append("#!/bin/bash\n# Generated gcloud commands for quick posture corrections\necho '[*] Starting quick CLI posture remediations...'\n")
    
    plan_md.append("# Cryptographic Posture Remediation Plan\n")
    plan_md.append("This document outlines the required actions to migrate identified classical/vulnerable algorithms to quantum-safe configurations.\n")
    plan_md.append("## Remediation Steps Summary\n")
    
    kms_count = 0
    ssl_count = 0
    cert_count = 0
    
    for f in findings:
        if f.get("status") == "PQC_COMPLIANT":
            continue
            
        res_name = f.get("resource_name", "")
        res_type = f.get("resource_type", "")
        algo = f.get("algorithm", "")
        base_name = res_name.split("/")[-1] if "/" in res_name else "resource"
        
        if res_type == "kms.CryptoKey":
            kms_count += 1
            # KMS Remediation Template
            tf_infra.append(f"""# Remediation for classical KMS key: {res_name}
resource "google_kms_crypto_key" "pqc_kek_{base_name}" {{
  name            = "pqc-wrapped-{base_name}"
  key_ring        = "projects/pqc-demo-project/locations/us-central1/keyRings/ring-1"
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s" # 90 days
  
  # Note: KMS does not support native HSM-based PQC keys yet.
  # This symmetric KEK wraps software-generated PQC key materials (e.g. ML-DSA/ML-KEM) in client apps.
  version_template {{
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }}
}}
""")
            gcloud_cmds.append(f"echo '[*] Rotating KMS Key {base_name} to symmetric hybrid wrap pattern...'")
            gcloud_cmds.append(f"gcloud kms keys versions create --key=pqc-wrapped-{base_name} --keyring=ring-1 --location=us-central1 --algorithm=google-symmetric-encryption\n")
            
            plan_md.append(f"- **[KMS Key]** `{res_name}` is classical ({algo}).")
            plan_md.append(f"  - *Action*: Deploy symmetric wrapping KEK (`pqc-wrapped-{base_name}`) to wrap ML-DSA/ML-KEM payload key pairs in-app.")
            
        elif res_type == "compute.SslPolicy":
            ssl_count += 1
            # SSL Policy Remediation
            tf_infra.append(f"""# Remediation for legacy SSL Policy: {res_name}
resource "google_compute_ssl_policy" "remediated_{base_name}" {{
  name            = "pqc-compat-{base_name}"
  profile         = "MODERN"
  min_tls_version = "TLS_1_3" # Enforces hybrid PQC key exchange
}}
""")
            
            # Org Policy Constraint
            tf_policies.append(f"""# Enforce TLS 1.3 restriction on load balancers
resource "google_org_policy_policy" "restrict_tls_version_{base_name}" {{
  name   = "projects/pqc-demo-project/policies/compute.restrictLoadBalancerCryptoPolicies"
  parent = "projects/pqc-demo-project"
  spec {{
    rules {{
      enforce = "TRUE"
    }}
  }}
}}
""")
            
            gcloud_cmds.append(f"echo '[*] Updating SSL Policy {base_name} to TLS 1.3...'")
            gcloud_cmds.append(f"gcloud compute ssl-policies update {base_name} --min-tls-version=TLS_1_3\n")
            
            plan_md.append(f"- **[SSL Policy]** `{res_name}` uses legacy TLS ({algo}).")
            plan_md.append(f"  - *Action*: Update policy to modern profile and restrict min version to `TLS_1_3` to enforce post-quantum cipher support.")
            
        elif res_type == "certificatemanager.Certificate":
            cert_count += 1
            # Cert plan
            plan_md.append(f"- **[Certificate]** `{res_name}` is classical RSA/ECDSA ({algo}).")
            plan_md.append("  - *Action*: Deploy hybrid dual-certificate wrappers on application endpoints to support classical + PQC clients during transition.")

    # Write files
    with open(os.path.join(output_dir, "remediate_infra.tf"), "w", encoding="utf-8") as f:
        f.write("\n".join(tf_infra))
    with open(os.path.join(output_dir, "remediate_org_policies.tf"), "w", encoding="utf-8") as f:
        f.write("\n".join(tf_policies))
    
    script_path = os.path.join(output_dir, "remediate.sh")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write("\n".join(gcloud_cmds))
        f.write("echo '[*] All CLI corrections queued.'\n")
    # Make script executable
    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass
        
    with open(os.path.join(output_dir, "remediation_plan.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(plan_md))
        
    print(f"[*] Policy-as-Code files written to directory: {output_dir}")
    print(f"    - Generated {kms_count} KMS, {ssl_count} SSL Policy, and {cert_count} Certificate remediation tasks.")

def main():
    parser = argparse.ArgumentParser(description="PQC Policy-as-Code and Remediation Manifest Generator")
    parser.add_argument("--report", default="pqc_compliance_report.json", help="Path to compliance scan findings JSON.")
    parser.add_argument("--output-dir", default="remediation", help="Target output directory for remediation code.")
    args = parser.parse_args()
    
    if not os.path.exists(args.report):
        print(f"[Error] Compliance report '{args.report}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(args.report, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read report JSON: {e}", file=sys.stderr)
        sys.exit(1)
        
    generate_remediation_plan(findings, args.output_dir)

if __name__ == "__main__":
    main()
