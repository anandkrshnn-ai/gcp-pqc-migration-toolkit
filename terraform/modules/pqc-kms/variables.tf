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
