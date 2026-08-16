import os
import sys
import json
import time
import subprocess

def format_pr_body(findings: list) -> str:
    """Renders a descriptive markdown summary of non-compliant assets for the PR description."""
    non_compliant = [f for f in findings if f.get("status") != "PQC_COMPLIANT"]
    if not non_compliant:
        return "No classical cryptographic posture drift or vulnerability detected."
        
    body = [
        "## Post-Quantum Cryptography (PQC) Auto-Remediation Plan",
        f"This automated PR contains security remediation configurations to rotate **{len(non_compliant)}** classical assets to quantum-safe alternatives.",
        "",
        "### Staged Remediation Assets:",
        "- `remediate_infra.tf` - Remediated Terraform templates",
        "- `remediate_org_policies.tf` - Org policy constraint manifests",
        "- `remediate.sh` - CLI posture corrections",
        "- `remediation_plan.md` - High-level migration runbook",
        "",
        "### Exposing Resources Details:",
    ]
    
    for f in non_compliant:
        res_name = f.get("resource_name", "")
        base_name = res_name.split("/")[-1] if "/" in res_name else "unknown"
        body.append(f"- **{f.get('resource_type')}** (`{base_name}`): uses classical `{f.get('algorithm')}` (HNDL Priority: `{f.get('hndl_priority')}`) ")
        
    return "\n".join(body)

def execute_git_workflow(output_dir: str, findings: list):
    """Executes git commands to stage files, commit to a patch branch, and pushes to remote."""
    branch_name = f"pqc-remediation-{int(time.time())}"
    
    try:
        # Check git status
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], check=True, capture_output=True)
    except Exception:
        print("[Error] Not inside a git repository. Skipping git workflow.", file=sys.stderr)
        return
        
    # Check out new branch
    print(f"[*] Creating new git branch: {branch_name}")
    subprocess.run(["git", "checkout", "-b", branch_name], check=True)
    
    # Add generated files
    print("[*] Staging remediation manifests...")
    subprocess.run(["git", "add", output_dir], check=True)
    subprocess.run(["git", "add", ".gitignore"], check=True)
    
    # Commit
    print("[*] Committing changes...")
    subprocess.run(["git", "commit", "-m", "sec: auto-generate PQC posture remediation manifests"], check=True)
    
    # Check if gh cli is installed to open a PR
    try:
        pr_body = format_pr_body(findings)
        # Save temp body file
        body_file = "pr_body.md"
        with open(body_file, "w", encoding="utf-8") as f:
            f.write(pr_body)
            
        print("[*] Pushing branch to origin...")
        subprocess.run(["git", "push", "origin", branch_name], check=True)
        
        print("[*] Creating GitHub Pull Request...")
        subprocess.run([
            "gh", "pr", "create",
            "--title", f"sec: auto-remediate {len(findings)} post-quantum exposures",
            "--body-file", body_file,
            "--label", "security,pqc-remediation"
        ], check=True)
        
        # Clean up temp file
        if os.path.exists(body_file):
            os.remove(body_file)
    except Exception as e:
        print(f"[Info] GitHub Pull Request could not be opened automatically (requires gh CLI & push access): {e}")
        print("Staged files are committed to branch locally. Run 'git push origin' and open a PR manually.")

def main():
    report_path = "pqc_compliance_report.json"
    output_dir = "remediation"
    
    if not os.path.exists(report_path):
        print(f"[Warning] Compliance report '{report_path}' not found. Cannot orchestrate PR.", file=sys.stderr)
        sys.exit(0)
        
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read report findings: {e}", file=sys.stderr)
        sys.exit(1)
        
    execute_git_workflow(output_dir, findings)

if __name__ == "__main__":
    main()
