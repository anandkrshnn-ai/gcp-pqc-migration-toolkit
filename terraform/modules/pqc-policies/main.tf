# Enforce post-quantum compliance using GCP Organization Policies

# Compute SslPolicy enforcing TLS 1.3 only
resource "google_compute_ssl_policy" "pqc_ssl_policy" {
  name            = "pqc-compliant-ssl-policy"
  project         = var.project_id
  profile         = "MODERN"
  min_tls_version = "TLS_1_3"
}

# Restrict load balancers to use PQC-friendly SSL Policies
resource "google_org_policy_policy" "restrict_tls" {
  name   = "projects/${var.project_id}/policies/compute.restrictLoadBalancerCryptoPolicies"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      values {
        allowed_values = ["projects/${var.project_id}/global/sslPolicies/${google_compute_ssl_policy.pqc_ssl_policy.name}"]
      }
    }
  }
}

# Enforce Binary Authorization on GKE clusters
resource "google_org_policy_policy" "enforce_binauth" {
  name   = "projects/${var.project_id}/policies/container.enforceBinaryAuthorization"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "true"
    }
  }
}
