# Cloud KMS Post-Quantum Hybrid Wrapping Enclave

This module provisions a classical Key Encryption Key (KEK) designed to wrap software-defined Post-Quantum Cryptography (PQC) private keys.

> [!WARNING]
> **Cryptographic Limitations**: Google Cloud KMS HSM modules do not natively support NIST PQC algorithms (e.g. ML-KEM). The key created by this module is a classical HSM key (symmetric or RSA). Wrapping and unwrapping of raw PQC key materials must be performed in application software, ideally inside secure enclaves such as **Google Cloud Confidential Space**.

## Inputs

| Name | Description | Type | Default | Required |
| :--- | :--- | :--- | :--- | :---: |
| `project_id` | GCP Project ID | `string` | n/a | yes |
| `location` | Location for the Key Ring | `string` | `"us-central1"` | no |
| `keyring_name` | Key Ring name | `string` | `"pqc-migration-keyring"` | no |
| `key_name` | KEK CryptoKey name | `string` | `"classical-hybrid-kek"` | no |
| `key_purpose` | CryptoKey purpose | `string` | `"ENCRYPT_DECRYPT"` | no |
| `key_algorithm` | CryptoKey algorithm | `string` | `"GOOGLE_SYMMETRIC_ENCRYPTION"` | no |
| `rotation_period` | Rotation interval in seconds | `string` | `"7776000s"` | no |
| `destroy_scheduled_duration` | Scheduled destruction delay | `string` | `"2592000s"` | no |
| `labels` | Resource labels | `map(string)` | `{ pqc-migration = "true" }` | no |
| `wrapping_users` | IAM members granted decrypter permissions | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| :--- | :--- |
| `keyring_id` | Resource ID of the created KMS Key Ring |
| `wrapping_key_id` | Resource ID of the KEK wrapping key |
