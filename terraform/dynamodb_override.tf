######################################################################
# GRC baseline — override file (merges into aws_dynamodb_table.intake
# defined in main.tf).
# GAP-02: bring the submissions table under a customer-managed key
# instead of the AWS-owned default.
# point_in_time_recovery: cheap, same 164.308(a)(7) contingency-plan
# theme as GAP-04's S3 versioning fix (checkov CKV_AWS_28).
######################################################################

resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_data.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}
