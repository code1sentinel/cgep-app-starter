######################################################################
# GRC baseline — override file (merges into aws_lambda_function.intake
# defined in main.tf).
# Encrypts the function's environment variables (INTAKE_TABLE,
# UPLOAD_BUCKET names) with a customer-managed key instead of the
# Lambda service default (checkov CKV_AWS_173). Reuses the S3 CMK
# rather than provisioning a fourth key for two non-sensitive resource
# identifiers.
######################################################################

resource "aws_lambda_function" "intake" {
  kms_key_arn = aws_kms_key.s3_data.arn
}
