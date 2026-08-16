variable "project_id" {
  type        = string
  description = "The GCP Project ID where PQC KMS resources will be deployed."
}

variable "location" {
  type        = string
  default     = "us-central1"
  description = "GCP location for key ring."
}

variable "keyring_name" {
  type        = string
  default     = "pqc-migration-keyring"
  description = "Name of the Cloud KMS Key Ring."
}

variable "key_name" {
  type        = string
  default     = "classical-hybrid-kek"
  description = "Name of the KMS KEK CryptoKey."
}

variable "key_purpose" {
  type        = string
  default     = "ENCRYPT_DECRYPT"
  description = "The cryptographic purpose of the wrapping KEK."
}

variable "key_algorithm" {
  type        = string
  default     = "GOOGLE_SYMMETRIC_ENCRYPTION"
  description = "The classical wrapping algorithm (typically GOOGLE_SYMMETRIC_ENCRYPTION or RSA_DECRYPT_OAEP_4096_SHA256)."
}

variable "rotation_period" {
  type        = string
  default     = "7776000s" # 90 days
  description = "The rotation period for the KEK in seconds."
}

variable "destroy_scheduled_duration" {
  type        = string
  default     = "2592000s" # 30 days
  description = "Duration to keep keys in the scheduled for destruction state."
}

variable "labels" {
  type = map(string)
  default = {
    pqc-migration = "true"
    env           = "production"
  }
  description = "Labels to apply to the KMS key."
}

variable "wrapping_users" {
  type        = list(string)
  default     = []
  description = "List of IAM members authorized to use this KEK wrapper (e.g. Service Accounts running Confidential Space)."
}
