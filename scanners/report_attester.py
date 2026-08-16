import json
import os
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEY_PATH = "pqc_attestation_key.pem"
PUB_KEY_PATH = "pqc_attestation_pub.pem"

def load_or_create_keys():
    """Loads or generates Ed25519 keypair for attestation signing."""
    if os.path.exists(KEY_PATH) and os.path.exists(PUB_KEY_PATH):
        try:
            with open(KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUB_KEY_PATH, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            return private_key, public_key
        except Exception as e:
            print(f"[Warning] Failed to load existing key: {e}. Regenerating new keys.", file=sys.stderr)

    # Generate new keypair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save keys
    with open(KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUB_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[*] Generated new attestation Ed25519 keys: {KEY_PATH} / {PUB_KEY_PATH}")
    return private_key, public_key

def canonicalize_payload(findings: list) -> bytes:
    """Produces a deterministic, sorted, whitespace-free bytes representation of the findings."""
    return json.dumps(findings, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sign_findings_report(findings: list) -> dict:
    """Signs the compliance findings payload and returns a signed envelope."""
    private_key, public_key = load_or_create_keys()
    
    canonical_data = canonicalize_payload(findings)
    signature = private_key.sign(canonical_data)
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return {
        "payload": findings,
        "signature": signature.hex(),
        "publicKey": pub_bytes.hex(),
        "algorithm": "Ed25519"
    }

def main():
    report_path = "pqc_compliance_report.json"
    output_path = "pqc_compliance_report.signed.json"
    
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
        
    if not os.path.exists(report_path):
        print(f"[Error] Compliance report file '{report_path}' not found.", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read JSON report: {e}", file=sys.stderr)
        sys.exit(1)
        
    signed_envelope = sign_findings_report(findings)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(signed_envelope, f, indent=2)
        
    print(f"[*] Attested compliance report saved to: {output_path}")

if __name__ == "__main__":
    main()
