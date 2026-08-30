######################################################################
# GRC baseline — override file (merges into aws_iam_role_policy.lambda_inline
# defined in main.tf).
# GAP-07: dynamodb:* / s3:* is over-broad. Scope to exactly what
# lambda/handler.py calls: PutItem on the table, PutObject under
# uploads/*, and the KMS actions needed to write through the CMKs
# in kms.tf now that GAP-01/GAP-02 enforce SSE-KMS.
######################################################################

resource "aws_iam_role_policy" "lambda_inline" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "IntakeTableWrite"
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "UploadsWrite"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.uploads.arn}/uploads/*"
      },
      {
        Sid    = "CmkUseForWrites"
        Effect = "Allow"
        Action = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [
          aws_kms_key.s3_data.arn,
          aws_kms_key.dynamodb_data.arn
        ]
      }
    ]
  })
}
