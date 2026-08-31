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

variable "evidence_vault_bucket_arn" {
  type        = string
  description = "ARN of the Layer 1 evidence vault (terraform/evidence-vault) the pipeline signs and uploads bundles into."
}
