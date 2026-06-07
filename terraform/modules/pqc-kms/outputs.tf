output "keyring_id" {
  value       = google_kms_key_ring.pqc_keyring.id
  description = "The fully qualified resource ID of the created KMS key ring."
}

output "wrapping_key_id" {
  value       = google_kms_crypto_key.classical_wrapping_key.id
  description = "Resource ID of the classical wrapping key."
}
