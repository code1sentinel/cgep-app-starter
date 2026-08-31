# terraform/oidc-trust/main.tf
#
# Persistent CI-supporting infrastructure: the GitHub<->AWS OIDC trust
# the pipeline authenticates through (no static AWS keys in GitHub,
# ever), and the S3 bucket holding Terraform's remote state so runs on
# GitHub's stateless runners see the same deployed reality we do.
# Same lifecycle reasoning as terraform/evidence-vault: bootstrapped
# once, survives the main workload's destroy/recreate cycles.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = "ci"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-capstone"
    }
  }
}

data "aws_caller_identity" "current" {}

######################################################################
# Remote state bucket.
######################################################################

resource "random_id" "state_suffix" { byte_length = 4 }

locals {
  state_bucket_name = "${var.project_name}-tfstate-${random_id.state_suffix.hex}"
}

resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket_name
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################################################
# GitHub OIDC trust.
######################################################################

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "acme-health-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        # Scoped to this one repo only. Widening this to repo:*:* trusts
        # every public GitHub repo to assume this role -- don't.
        #
        # GitHub's OIDC token embeds immutable numeric org/repo IDs in
        # the sub claim -- repo:OWNER@ORG_ID/REPO@REPO_ID:event -- not
        # the plain repo:OWNER/REPO:* format older docs show. Pinning
        # to the numeric IDs (not just the names) is actually stronger:
        # trust survives a rename and doesn't silently re-attach if the
        # repo were ever deleted and a new one recreated under the same
        # name. Discovered via a debug step dumping the real token
        # (github.com/code1sentinel/cgep-app-starter, org id 228478940,
        # repo id 1345892945) after the plain-name condition failed
        # every retry with "Not authorized to perform
        # sts:AssumeRoleWithWebIdentity".
        StringLike = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}@${var.github_org_id}/${var.github_repo}@${var.github_repo_id}:*" }
      }
    }]
  })
}

######################################################################
# Least-privilege policy for the pipeline role.
# Grouped by service, one statement per concern, scoped by resource
# ARN wherever the service supports it. EC2/VPC actions largely don't
# support resource-level permissions, so those stay Resource = "*".
######################################################################

data "aws_iam_policy_document" "grc_gate" {
  statement {
    sid    = "TerraformStateAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
      "s3:GetBucketLocation", "s3:GetBucketVersioning"
    ]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }

  statement {
    sid    = "EvidenceVaultWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject", "s3:GetObject", "s3:GetBucketLocation"
    ]
    resources = [var.evidence_vault_bucket_arn, "${var.evidence_vault_bucket_arn}/*"]
  }

  statement {
    sid    = "Ec2NetworkingBroad"
    effect = "Allow"
    # VPC/subnet/route-table/IGW actions: EC2 doesn't support
    # resource-level IAM for most of these, so this is Resource = "*"
    # by AWS's own constraint, not a shortcut.
    actions = [
      "ec2:DescribeVpcs", "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute", "ec2:DescribeVpcAttribute",
      "ec2:DescribeSubnets", "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
      "ec2:DescribeInternetGateways", "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
      "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
      "ec2:DescribeRouteTables", "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
      "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
      "ec2:ReplaceRouteTableAssociation", "ec2:DescribeAvailabilityZones",
      "ec2:CreateTags", "ec2:DeleteTags", "ec2:DescribeTags"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DynamoDbTable"
    effect = "Allow"
    actions = [
      "dynamodb:CreateTable", "dynamodb:DescribeTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
      "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:ListTagsOfResource",
      "dynamodb:DescribeTimeToLive", "dynamodb:DescribeContinuousBackups"
    ]
    resources = ["arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.project_name}-*"]
  }

  statement {
    sid    = "S3WorkloadBuckets"
    effect = "Allow"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:ListBucket", "s3:GetBucketLocation",
      "s3:GetBucketVersioning", "s3:PutBucketVersioning",
      "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
      "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
      "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketTagging", "s3:PutBucketTagging"
    ]
    resources = [
      "arn:aws:s3:::${var.project_name}-*",
    ]
  }

  statement {
    sid    = "IamRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole", "iam:GetRole", "iam:DeleteRole", "iam:UpdateRole",
      "iam:TagRole", "iam:UntagRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
      "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:GetPolicy", "iam:GetPolicyVersion"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-*"]
  }

  statement {
    sid       = "IamPassRoleToLambda"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid       = "IamAwsManagedPolicyRead"
    effect    = "Allow"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
  }

  statement {
    sid    = "KmsKeyManagement"
    effect = "Allow"
    actions = [
      "kms:CreateKey", "kms:DescribeKey", "kms:EnableKeyRotation", "kms:GetKeyRotationStatus",
      "kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      "kms:DisableKey", "kms:EnableKey", "kms:TagResource", "kms:UntagResource", "kms:ListResourceTags"
    ]
    resources = ["*"] # key ARNs aren't known before creation; scoped by account via key policy instead
  }

  statement {
    sid    = "KmsAliasManagement"
    effect = "Allow"
    actions = [
      "kms:CreateAlias", "kms:DeleteAlias", "kms:ListAliases", "kms:UpdateAlias"
    ]
    resources = ["arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alias/${var.project_name}-*"]
  }

  statement {
    sid    = "LambdaFunction"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction", "lambda:GetFunction", "lambda:GetFunctionConfiguration",
      "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction",
      "lambda:AddPermission", "lambda:RemovePermission", "lambda:GetPolicy",
      "lambda:TagResource", "lambda:UntagResource", "lambda:ListTags", "lambda:ListVersionsByFunction"
    ]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.project_name}-*"]
  }

  statement {
    sid    = "ApiGatewayBroad"
    effect = "Allow"
    # API Gateway v2's IAM model is coarse-grained (no useful per-API
    # resource scoping for the actions Terraform needs here).
    actions   = ["apigateway:*"]
    resources = ["arn:aws:apigateway:${var.aws_region}::/apis*"]
  }

  statement {
    sid    = "CloudTrailManagement"
    effect = "Allow"
    actions = [
      "cloudtrail:CreateTrail", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors", "cloudtrail:GetEventSelectors",
      "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:AddTags", "cloudtrail:ListTags"
    ]
    resources = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${var.project_name}-*"]
  }

  statement {
    sid    = "EventBridgeRules"
    effect = "Allow"
    actions = [
      "events:PutRule", "events:DescribeRule", "events:DeleteRule",
      "events:PutTargets", "events:RemoveTargets", "events:ListTargetsByRule",
      "events:ListTagsForResource", "events:TagResource"
    ]
    resources = ["arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${var.project_name}-*"]
  }

  statement {
    sid    = "SnsTopic"
    effect = "Allow"
    actions = [
      "sns:CreateTopic", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:DeleteTopic",
      "sns:Subscribe", "sns:Unsubscribe", "sns:ListSubscriptionsByTopic",
      "sns:TagResource", "sns:UntagResource"
    ]
    resources = ["arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.project_name}-*"]
  }

  statement {
    sid    = "SqsQueue"
    effect = "Allow"
    actions = [
      "sqs:CreateQueue", "sqs:GetQueueAttributes", "sqs:SetQueueAttributes", "sqs:DeleteQueue",
      "sqs:GetQueueUrl", "sqs:TagQueue", "sqs:UntagQueue", "sqs:ListQueueTags"
    ]
    resources = ["arn:aws:sqs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.project_name}-*"]
  }

  statement {
    sid       = "StsIdentity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "grc_gate" {
  name   = "grc-gate-least-privilege"
  role   = aws_iam_role.grc_gate.id
  policy = data.aws_iam_policy_document.grc_gate.json
}
