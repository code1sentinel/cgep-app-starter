# terraform/evidence-vault/variables.tf
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "acme-health-intake"
}

variable "lock_mode" {
  type        = string
  description = "COMPLIANCE for real evidence (default); GOVERNANCE only if you need to bypass-delete during development."
  default     = "COMPLIANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object. Was 1 day during pipeline development (so COMPLIANCE-mode test uploads expired quickly); raised to 6 years (2190 days) for real evidence, matching HIPAA's own documentation-retention requirement (45 CFR 164.316(b)(2)(i)) rather than an arbitrary 'long enough' number."
  default     = 2190
}
