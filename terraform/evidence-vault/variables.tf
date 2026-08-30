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
  description = "Default retention applied to every uploaded object. Kept short (1 day) by default so COMPLIANCE-mode test uploads during pipeline development expire quickly; raise it deliberately for real capstone evidence."
  default     = 1
}
