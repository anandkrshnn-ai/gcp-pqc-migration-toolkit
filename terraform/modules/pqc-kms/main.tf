# Cloud KMS Post-Quantum Cryptography Hybrid Key Wrapping Enclave Setup
#
# NOTE: Cloud KMS HSM modules do not natively support NIST PQC algorithms (e.g. ML-KEM).
# This configuration creates a classical Key Encryption Key (KEK) using GOOGLE_SYMMETRIC_ENCRYPTION
# or RSA-4096. This KEK is used by external software wrapper applications (such as those running 
# inside Google Cloud Confidential Space or GKE enclaves) to securely wrap/unwrap post-quantum
# key material.

resource "google_kms_key_ring" "pqc_keyring" {
  name     = var.keyring_name
  location = var.location
  project  = var.project_id
}

# Classical primary KEK used for wrapping software-defined PQC keys
resource "google_kms_crypto_key" "classical_wrapping_key" {
  name            = var.key_name
  key_ring        = google_kms_key_ring.pqc_keyring.id
  purpose         = var.key_purpose
  rotation_period = var.rotation_period

  # Ensure keys are not accidentally deleted in production environments
  destroy_scheduled_duration = var.destroy_scheduled_duration

  version_template {
    algorithm        = var.key_algorithm
    protection_level = "HSM"
  }

  labels = var.labels
}

# IAM policy binding to define who/what can decrypt/unwrap using the KEK wrapper (e.g., GKE Service Accounts)
resource "google_kms_crypto_key_iam_binding" "wrapping_key_users" {
  count         = length(var.wrapping_users) > 0 ? 1 : 0
  crypto_key_id = google_kms_crypto_key.classical_wrapping_key.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  members       = var.wrapping_users
}
