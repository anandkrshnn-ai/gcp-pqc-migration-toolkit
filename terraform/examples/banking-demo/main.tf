# Banking Demo Sandbox Deployment - Post-Quantum Cryptography Architecture

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

variable "project_id" {
  type        = string
  description = "The target GCP Project ID for the banking infrastructure."
}

# 1. PQC KMS Module: Provision KeyRings and HSM classical-hybrid wrapping keys
module "banking_pqc_kms" {
  source       = "../../modules/pqc-kms"
  project_id   = var.project_id
  location     = "us-central1"
  keyring_name = "retail-banking-kms-ring"
}

# 2. PQC Org Policy Module: Restrict Load Balancers to TLS 1.3+ profiles
module "banking_pqc_policies" {
  source     = "../../modules/pqc-policies"
  project_id = var.project_id
}

output "banking_keyring" {
  value       = module.banking_pqc_kms.keyring_id
  description = "The retail banking KMS key ring ID."
}

output "banking_wrapping_key" {
  value       = module.banking_pqc_kms.wrapping_key_id
  description = "The retail banking HSM wrapping key ID."
}
