# GCP Post-Quantum Org Policies Enforcer

This module configures post-quantum migration guards using GCP Resource Manager Organization Policies.

## Policies Enforced

1. **SSL Policy Restriction** (`compute.restrictLoadBalancerCryptoPolicies`): Restricts Load Balancer SSL profiles to TLS 1.3+ modern profiles only.
2. **GKE Binary Authorization Enforcer** (`container.enforceBinaryAuthorization`): Requires Binary Authorization checks on GKE clusters to prepare for signing key attestations.

## Inputs

| Name | Description | Type | Default | Required |
| :--- | :--- | :--- | :--- | :---: |
| `project_id` | Target GCP Project ID to apply policies | `string` | n/a | yes |
