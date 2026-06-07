# Cloud KMS PQC Hybrid Cryptography Setup

resource "google_kms_key_ring" "pqc_keyring" {
  name     = var.keyring_name
  location = var.location
  project  = var.project_id
}

# Classical primary key used for wrapping PQC software keys
resource "google_kms_crypto_key" "classical_wrapping_key" {
  name     = "classical-wrapping-key"
  key_ring = google_kms_key_ring.pqc_keyring.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }
}
