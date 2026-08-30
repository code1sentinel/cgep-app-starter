######################################################################
# GRC baseline — override file (merges into aws_dynamodb_table.intake
# defined in main.tf).
# GAP-02: bring the submissions table under a customer-managed key
# instead of the AWS-owned default.
######################################################################

resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_data.arn
  }
}
