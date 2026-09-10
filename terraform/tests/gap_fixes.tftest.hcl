# Native `terraform test` coverage for the five closed gaps.
#
# These are plan-time assertions against the real root module and real
# AWS provider (no mocking) -- `command = plan` computes a real plan but
# never applies (no resources created, no cost -- notably, a `command =
# apply` run here would mean creating real KMS CMKs, and AWS bills a
# full month for a CMK the instant it's created, even if destroyed a
# second later, so plan-only is a deliberate cost choice, not just a
# convenience). Rego (policies/) already gives negative-path coverage
# (compliant vs non-compliant fixtures per gap); this suite complements
# it with infra-level assertions tied directly to the actual resource
# graph, not a parsed plan.json.
#
# A plan against a from-scratch state can't know provider-assigned
# attributes (ARNs, IDs) until apply -- these overrides give the four
# cross-referenced resources a known literal ARN/ID during planning so
# assertions can check that GAP-01/02/07's fixes point at *the specific
# CMK/bucket/table*, not just at "some" one.
override_resource {
  target          = aws_kms_key.s3_data
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001"
  }
}

override_resource {
  target          = aws_kms_key.dynamodb_data
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000002"
  }
}

override_resource {
  target          = aws_s3_bucket.uploads
  override_during = plan
  values = {
    id  = "mock-uploads-bucket"
    arn = "arn:aws:s3:::mock-uploads-bucket"
  }
}

override_resource {
  target          = aws_dynamodb_table.intake
  override_during = plan
  values = {
    arn = "arn:aws:dynamodb:us-east-1:000000000000:table/mock-intake-table"
  }
}

run "gap01_s3_uploads_bucket_uses_kms_cmk" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.uploads.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "GAP-01: uploads bucket SSE algorithm must be aws:kms, not the AWS-managed SSE-S3 default."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.uploads.rule).apply_server_side_encryption_by_default).kms_master_key_id == aws_kms_key.s3_data.arn
    error_message = "GAP-01: uploads bucket must be encrypted with the dedicated customer-managed S3 CMK, not any other key."
  }
}

run "gap02_dynamodb_table_uses_kms_cmk" {
  command = plan

  assert {
    condition     = one(aws_dynamodb_table.intake.server_side_encryption).enabled == true
    error_message = "GAP-02: DynamoDB table encryption must be explicitly enabled."
  }

  assert {
    condition     = one(aws_dynamodb_table.intake.server_side_encryption).kms_key_arn == aws_kms_key.dynamodb_data.arn
    error_message = "GAP-02: DynamoDB table must use the dedicated customer-managed DynamoDB CMK, not the AWS-owned default key."
  }
}

run "gap03_uploads_bucket_denies_insecure_transport" {
  command = plan

  assert {
    condition     = strcontains(aws_s3_bucket_policy.uploads.policy, "aws:SecureTransport")
    error_message = "GAP-03: uploads bucket policy must reference the aws:SecureTransport condition key."
  }

  assert {
    condition     = strcontains(aws_s3_bucket_policy.uploads.policy, "\"Deny\"")
    error_message = "GAP-03: uploads bucket policy must include a Deny statement (not merely reference SecureTransport)."
  }
}

run "gap04_uploads_bucket_versioning_enabled" {
  command = plan

  assert {
    condition     = one(aws_s3_bucket_versioning.uploads.versioning_configuration).status == "Enabled"
    error_message = "GAP-04: uploads bucket versioning must be Enabled."
  }
}

run "gap07_lambda_role_policy_has_no_wildcard_actions" {
  command = plan

  assert {
    condition     = !strcontains(aws_iam_role_policy.lambda_inline.policy, "\"dynamodb:*\"")
    error_message = "GAP-07: Lambda inline policy must not grant dynamodb:* -- least privilege requires the exact actions the handler calls."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.lambda_inline.policy, "\"s3:*\"")
    error_message = "GAP-07: Lambda inline policy must not grant s3:* -- least privilege requires the exact actions the handler calls."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.lambda_inline.policy, "dynamodb:PutItem")
    error_message = "GAP-07: Lambda inline policy must still grant the specific action the handler actually needs (dynamodb:PutItem) -- least privilege isn't the same as no privilege."
  }
}
