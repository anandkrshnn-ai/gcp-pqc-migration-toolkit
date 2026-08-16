import json
import sys
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def verify_signed_report(signed_envelope: dict) -> bool:
    """Verifies the Ed25519 signature of the compliance report envelope."""
    try:
        findings = signed_envelope["payload"]
        signature_hex = signed_envelope["signature"]
        pub_key_hex = signed_envelope["publicKey"]
        algo = signed_envelope.get("algorithm", "Ed25519")
    except KeyError as e:
        print(f"[Error] Invalid signed report structure: Missing field {e}", file=sys.stderr)
        return False

    if algo != "Ed25519":
        print(f"[Error] Unsupported attestation algorithm: {algo}", file=sys.stderr)
        return False

    try:
        signature = bytes.fromhex(signature_hex)
        pub_key_bytes = bytes.fromhex(pub_key_hex)
    except ValueError as e:
        print(f"[Error] Invalid hex formatting in key or signature: {e}", file=sys.stderr)
        return False

    try:
        # Load raw public key bytes
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
    except Exception as e:
        print(f"[Error] Failed to load public key: {e}", file=sys.stderr)
        return False

    # Canonicalize payload for matching deterministic representation
    # Deterministic JSON serialization
    canonical_data = json.dumps(findings, sort_keys=True, separators=(',', ':')).encode('utf-8')

    try:
        public_key.verify(signature, canonical_data)
        return True
    except InvalidSignature:
        return False

def main():
    report_path = "pqc_compliance_report.signed.json"
    if len(sys.argv) > 1:
        report_path = sys.argv[1]

    if not os.path.exists(report_path):
        print(f"[Error] Signed report file '{report_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            signed_envelope = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read signed JSON report: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Verifying cryptographic signature on: {report_path}")
    is_valid = verify_signed_report(signed_envelope)
    
    if is_valid:
        print("[SUCCESS] Cryptographic Signature: VALID. Report contents are untampered and verified.")
        sys.exit(0)
    else:
        print("[ERROR] Cryptographic Signature: INVALID. Report contents have been tampered with or modified!", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
