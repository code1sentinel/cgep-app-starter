# terraform/evidence-vault/outputs.tf
output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to the Layer 3 pipeline's upload step."
}

output "vault_arn" {
  value = aws_s3_bucket.vault.arn
}

output "vault_kms_key_arn" {
  value = aws_kms_key.vault.arn
}
