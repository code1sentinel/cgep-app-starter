######################################################################
# GRC baseline — customer-managed KMS keys.
# Closes GAP-01 (S3 uploads bucket) and GAP-02 (DynamoDB table):
# both starter resources default to AWS-owned/AWS-managed keys, not
# keys under customer custody. HIPAA 164.312(a)(2)(iv).
######################################################################

data "aws_caller_identity" "current" {}

# --- S3 data key (uploads bucket) -----------------------------------

resource "aws_kms_key" "s3_data" {
  description         = "CMK for Acme Health S3 uploads bucket (PHI attachments)."
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3ServiceUse"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      },
      {
        Sid       = "AllowLambdaExecutionRole"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "s3_data" {
  name          = "alias/acme-health-s3-data-${local.suffix}"
  target_key_id = aws_kms_key.s3_data.key_id
}

# --- DynamoDB data key (submissions table) ---------------------------

resource "aws_kms_key" "dynamodb_data" {
  description         = "CMK for Acme Health DynamoDB submissions table (PHI records)."
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowDynamoDBServiceUse"
        Effect    = "Allow"
        Principal = { Service = "dynamodb.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"]
        Resource  = "*"
      },
      {
        Sid       = "AllowLambdaExecutionRole"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "dynamodb_data" {
  name          = "alias/acme-health-dynamodb-data-${local.suffix}"
  target_key_id = aws_kms_key.dynamodb_data.key_id
}
