# terraform/oidc-trust/outputs.tf
output "role_arn" {
  value       = aws_iam_role.grc_gate.arn
  description = "Set as the AWS_ROLE_ARN repo variable for the GitHub Actions workflow."
}

output "state_bucket_name" {
  value       = aws_s3_bucket.state.id
  description = "Set as the TF_STATE_BUCKET repo variable. Also used in terraform/backend.tf's -backend-config."
}
