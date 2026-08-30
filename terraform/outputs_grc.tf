######################################################################
# GRC baseline — additional outputs (starter's outputs.tf untouched).
######################################################################

output "kms_s3_key_arn" {
  value       = aws_kms_key.s3_data.arn
  description = "CMK protecting the uploads S3 bucket (GAP-01)."
}

output "kms_dynamodb_key_arn" {
  value       = aws_kms_key.dynamodb_data.arn
  description = "CMK protecting the DynamoDB submissions table (GAP-02)."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "Multi-region CloudTrail trail ARN."
}
