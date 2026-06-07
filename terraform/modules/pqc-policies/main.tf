# Enforce post-quantum compliance using GCP Organization Policies

# Restrict legacy TLS versions to enforce TLS 1.3 only
resource "google_org_policy_policy" "restrict_tls" {
  name   = "projects/${var.project_id}/policies/compute.restrictLoadBalancerCryptoPolicies"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      allow {
        values = ["projects/${var.project_id}/global/sslPolicies/pqc-compliant-ssl-policy"]
      }
    }
  }
}
