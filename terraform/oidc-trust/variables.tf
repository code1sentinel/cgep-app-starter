# terraform/oidc-trust/variables.tf
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "acme-health-intake"
}

variable "github_org" {
  type        = string
  description = "GitHub org or user that owns the capstone repo."
  default     = "code1sentinel"
}

variable "github_repo" {
  type        = string
  description = "Capstone repo name."
  default     = "cgep-app-starter"
}

variable "github_org_id" {
  type        = string
  description = "Numeric GitHub org/user ID -- GitHub's OIDC sub claim pins to this, not just the name (survives renames). Find via: gh api users/<org> --jq .id"
  default     = "228478940"
}

variable "github_repo_id" {
  type        = string
  description = "Numeric GitHub repo ID. Find via: gh api repos/<org>/<repo> --jq .id"
  default     = "1345892945"
}

variable "evidence_vault_bucket_arn" {
  type        = string
  description = "ARN of the Layer 1 evidence vault (terraform/evidence-vault) the pipeline signs and uploads bundles into."
}

variable "evidence_vault_kms_key_arn" {
  type        = string
  description = "ARN of the evidence vault's CMK -- the vault bucket enforces SSE-KMS, so PutObject needs kms:GenerateDataKey on this key too, not just S3 permissions."
}
