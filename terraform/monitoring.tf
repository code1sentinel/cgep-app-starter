######################################################################
# GRC baseline — continuous monitoring & detection.
# CloudTrail (cloudtrail.tf) already records every management API call.
# These EventBridge rules watch that stream for the specific action
# that would re-open one of the five gaps this capstone closed, and
# alert immediately rather than waiting for the next scheduled scan.
# Complements the pre-deploy Rego gate in policies/ with a post-deploy
# detective control — "prevent" and "detect" for the same five gaps.
######################################################################

variable "alert_email" {
  type        = string
  description = "Address that receives compliance drift alerts from monitoring.tf."
  default     = "code1sentinel@gmail.com"
}

resource "aws_sns_topic" "compliance_alerts" {
  name = "${local.name_prefix}-compliance-alerts-${local.suffix}"
  # AWS-managed key: this topic only carries alert metadata (which
  # control fired, on which resource), not PHI, so a dedicated CMK
  # isn't warranted the way it is for the uploads bucket / table.
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "compliance_alerts_email" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "compliance_alerts_topic" {
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.compliance_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "compliance_alerts" {
  arn    = aws_sns_topic.compliance_alerts.arn
  policy = data.aws_iam_policy_document.compliance_alerts_topic.json
}

# Shared dead-letter queue: if SNS delivery ever fails, the event lands
# here instead of silently vanishing.
resource "aws_sqs_queue" "monitoring_dlq" {
  name                    = "${local.name_prefix}-monitoring-dlq-${local.suffix}"
  sqs_managed_sse_enabled = true
}

data "aws_iam_policy_document" "monitoring_dlq" {
  statement {
    sid       = "AllowEventBridgeSend"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.monitoring_dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "monitoring_dlq" {
  queue_url = aws_sqs_queue.monitoring_dlq.id
  policy    = data.aws_iam_policy_document.monitoring_dlq.json
}

locals {
  # Every event rule below targets the same topic the same way, so the
  # target block is written once and reused per rule.
  event_target_common = {
    arn             = aws_sns_topic.compliance_alerts.arn
    dead_letter_arn = aws_sqs_queue.monitoring_dlq.arn
  }
}

######################################################################
# GAP-01 — S3 CMK lifecycle. 164.312(a)(2)(iv).
# Fires if anyone disables or schedules deletion of the key protecting
# the uploads bucket, which would silently break SSE-KMS on next write.
######################################################################

resource "aws_cloudwatch_event_rule" "gap01_s3_kms_key_lifecycle" {
  name        = "${local.name_prefix}-gap01-s3-kms-lifecycle-${local.suffix}"
  description = "GAP-01 / 164.312(a)(2)(iv): alerts if the S3 uploads CMK is disabled or scheduled for deletion."

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DisableKey", "ScheduleKeyDeletion"]
      requestParameters = {
        keyId = [aws_kms_key.s3_data.arn]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "gap01_s3_kms_key_lifecycle" {
  rule = aws_cloudwatch_event_rule.gap01_s3_kms_key_lifecycle.name
  arn  = local.event_target_common.arn
  dead_letter_config { arn = local.event_target_common.dead_letter_arn }
  depends_on = [aws_sns_topic_policy.compliance_alerts, aws_sqs_queue_policy.monitoring_dlq]
}

######################################################################
# GAP-02 — DynamoDB CMK lifecycle. 164.312(a)(2)(iv).
######################################################################

resource "aws_cloudwatch_event_rule" "gap02_dynamodb_kms_key_lifecycle" {
  name        = "${local.name_prefix}-gap02-dynamodb-kms-lifecycle-${local.suffix}"
  description = "GAP-02 / 164.312(a)(2)(iv): alerts if the DynamoDB CMK is disabled or scheduled for deletion."

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DisableKey", "ScheduleKeyDeletion"]
      requestParameters = {
        keyId = [aws_kms_key.dynamodb_data.arn]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "gap02_dynamodb_kms_key_lifecycle" {
  rule = aws_cloudwatch_event_rule.gap02_dynamodb_kms_key_lifecycle.name
  arn  = local.event_target_common.arn
  dead_letter_config { arn = local.event_target_common.dead_letter_arn }
  depends_on = [aws_sns_topic_policy.compliance_alerts, aws_sqs_queue_policy.monitoring_dlq]
}

######################################################################
# GAP-03 — uploads bucket policy changed. 164.312(e)(1).
# The SecureTransport-deny policy (s3_overrides.tf) lives in a
# resource anyone with s3:PutBucketPolicy could overwrite outside
# Terraform. Alert on any write or delete of that policy.
######################################################################

resource "aws_cloudwatch_event_rule" "gap03_s3_bucket_policy_change" {
  name        = "${local.name_prefix}-gap03-s3-policy-change-${local.suffix}"
  description = "GAP-03 / 164.312(e)(1): alerts if the uploads bucket's SecureTransport-deny policy is replaced or removed outside Terraform."

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketPolicy", "DeleteBucketPolicy"]
      requestParameters = {
        bucketName = [aws_s3_bucket.uploads.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "gap03_s3_bucket_policy_change" {
  rule = aws_cloudwatch_event_rule.gap03_s3_bucket_policy_change.name
  arn  = local.event_target_common.arn
  dead_letter_config { arn = local.event_target_common.dead_letter_arn }
  depends_on = [aws_sns_topic_policy.compliance_alerts, aws_sqs_queue_policy.monitoring_dlq]
}

######################################################################
# GAP-04 — uploads bucket versioning suspended. 164.308(a)(7).
######################################################################

resource "aws_cloudwatch_event_rule" "gap04_s3_versioning_suspended" {
  name        = "${local.name_prefix}-gap04-s3-versioning-${local.suffix}"
  description = "GAP-04 / 164.308(a)(7): alerts if versioning on the uploads bucket is suspended outside Terraform."

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketVersioning"]
      requestParameters = {
        bucketName = [aws_s3_bucket.uploads.id]
        VersioningConfiguration = {
          Status = ["Suspended"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "gap04_s3_versioning_suspended" {
  rule = aws_cloudwatch_event_rule.gap04_s3_versioning_suspended.name
  arn  = local.event_target_common.arn
  dead_letter_config { arn = local.event_target_common.dead_letter_arn }
  depends_on = [aws_sns_topic_policy.compliance_alerts, aws_sqs_queue_policy.monitoring_dlq]
}

######################################################################
# GAP-07 — Lambda inline IAM policy touched. 164.312(a)(1).
# Unlike the Rego check in policies/gap07_iam_least_privilege.rego,
# this doesn't try to parse the policy content (which is only knowable
# once the resource already exists). It alerts on any write to the
# policy at all, so a human reviews whatever changed.
######################################################################

resource "aws_cloudwatch_event_rule" "gap07_iam_policy_change" {
  name        = "${local.name_prefix}-gap07-iam-policy-change-${local.suffix}"
  description = "GAP-07 / 164.312(a)(1): alerts if the Lambda's inline IAM policy is modified or removed outside Terraform."

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutRolePolicy", "DeleteRolePolicy"]
      requestParameters = {
        roleName = [aws_iam_role.lambda.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "gap07_iam_policy_change" {
  rule = aws_cloudwatch_event_rule.gap07_iam_policy_change.name
  arn  = local.event_target_common.arn
  dead_letter_config { arn = local.event_target_common.dead_letter_arn }
  depends_on = [aws_sns_topic_policy.compliance_alerts, aws_sqs_queue_policy.monitoring_dlq]
}
