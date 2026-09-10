"""Detection-logic tests for terraform/monitoring.tf's EventBridge rules.

Each rule watches CloudTrail for the specific API call that would re-open
one of the five closed gaps. These tests don't reimplement EventBridge's
match semantics -- they call the real `events:TestEventPattern` API
(stateless, no resources touched) with the rule's *actual deployed*
event_pattern (pulled live from Terraform state, so a fixture can never
silently drift from what's really running) against realistic CloudTrail
event fixtures.

Positive cases: the exact dangerous call the rule exists to catch.
Negative cases: a safe/read-only call on the same resource, and the same
dangerous call on a *different* resource of the same type -- the second
one is the case that matters most, since a rule scoped to the wrong ARN
would pass every "does it fire at all" check while alerting on nothing,
or everything.

Requires AWS credentials with events:TestEventPattern (read-only, no
resource access) and read access to the terraform/ remote state.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import boto3
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TF_DIR = REPO_ROOT / os.environ.get("TF_WORKING_DIR", "terraform")
TERRAFORM_BIN = os.environ.get("TERRAFORM_BIN", "terraform")


@pytest.fixture(scope="session")
def tf_resources():
    proc = subprocess.run(
        [TERRAFORM_BIN, f"-chdir={TF_DIR}", "show", "-json"],
        capture_output=True, text=True, check=True,
    )
    state = json.loads(proc.stdout)
    return state["values"]["root_module"]["resources"]


@pytest.fixture(scope="session")
def events_client():
    return boto3.client("events")


def _pattern_for(tf_resources, rule_name):
    for r in tf_resources:
        if r["type"] == "aws_cloudwatch_event_rule" and r["name"] == rule_name:
            return r["values"]["event_pattern"]
    raise AssertionError(f"no aws_cloudwatch_event_rule named {rule_name!r} in state")


def _attr(tf_resources, resource_type, resource_name, attr):
    for r in tf_resources:
        if r["type"] == resource_type and r["name"] == resource_name:
            return r["values"][attr]
    raise AssertionError(f"no {resource_type}.{resource_name} in state")


# Placeholder account id (AWS's own documentation example value). The
# monitoring.tf event patterns match only on source / detail-type /
# eventName / requestParameters, never on account or userIdentity, so
# this value is cosmetic to the assertions -- kept as a placeholder so
# no real account id lands in version control.
_ACCOUNT = "123456789012"


def _cloudtrail_event(source, event_name, request_parameters):
    """Minimal but realistic 'AWS API Call via CloudTrail' event as delivered to EventBridge."""
    return {
        "version": "0",
        "id": "11111111-2222-3333-4444-555555555555",
        "detail-type": "AWS API Call via CloudTrail",
        "source": source,
        "account": _ACCOUNT,
        "time": "2026-09-10T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "eventVersion": "1.08",
            "eventTime": "2026-09-10T00:00:00Z",
            "eventSource": source.replace("aws.", "") + ".amazonaws.com",
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.5",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{_ACCOUNT}:user/some-user"},
            "requestParameters": request_parameters,
            "responseElements": None,
        },
    }


def _matches(events_client, pattern, event):
    resp = events_client.test_event_pattern(
        EventPattern=pattern, Event=json.dumps(event),
    )
    return resp["Result"]


# All resource identifiers below are read live from terraform state (not
# hardcoded), so this suite keeps working across this project's normal
# destroy/redeploy cycles instead of pinning to one deployment's
# random_id suffix.


@pytest.fixture(scope="session")
def resource_ids(tf_resources):
    return {
        "s3_cmk_arn": _attr(tf_resources, "aws_kms_key", "s3_data", "arn"),
        "dynamodb_cmk_arn": _attr(tf_resources, "aws_kms_key", "dynamodb_data", "arn"),
        "uploads_bucket": _attr(tf_resources, "aws_s3_bucket", "uploads", "id"),
        "trail_bucket": _attr(tf_resources, "aws_s3_bucket", "trail", "id"),
        "lambda_role": _attr(tf_resources, "aws_iam_role", "lambda", "name"),
    }


class TestGap01S3KmsKeyLifecycle:
    RULE = "gap01_s3_kms_key_lifecycle"

    @pytest.mark.parametrize("event_name", ["DisableKey", "ScheduleKeyDeletion"])
    def test_matches_dangerous_call_on_the_s3_cmk(self, tf_resources, resource_ids, events_client, event_name):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.kms", event_name, {"keyId": resource_ids["s3_cmk_arn"]})
        assert _matches(events_client, pattern, event) is True

    def test_ignores_safe_call_on_the_same_key(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.kms", "ListKeys", {"keyId": resource_ids["s3_cmk_arn"]})
        assert _matches(events_client, pattern, event) is False

    def test_ignores_dangerous_call_on_a_different_key(self, tf_resources, resource_ids, events_client):
        """The DynamoDB CMK is a real key in this account -- disabling it is
        GAP-02's rule's problem, not GAP-01's. A rule that isn't actually
        scoped to the S3 key would wrongly fire here."""
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.kms", "DisableKey", {"keyId": resource_ids["dynamodb_cmk_arn"]})
        assert _matches(events_client, pattern, event) is False


class TestGap02DynamodbKmsKeyLifecycle:
    RULE = "gap02_dynamodb_kms_key_lifecycle"

    @pytest.mark.parametrize("event_name", ["DisableKey", "ScheduleKeyDeletion"])
    def test_matches_dangerous_call_on_the_dynamodb_cmk(self, tf_resources, resource_ids, events_client, event_name):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.kms", event_name, {"keyId": resource_ids["dynamodb_cmk_arn"]})
        assert _matches(events_client, pattern, event) is True

    def test_ignores_dangerous_call_on_a_different_key(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.kms", "DisableKey", {"keyId": resource_ids["s3_cmk_arn"]})
        assert _matches(events_client, pattern, event) is False


class TestGap03S3BucketPolicyChange:
    RULE = "gap03_s3_bucket_policy_change"

    @pytest.mark.parametrize("event_name", ["PutBucketPolicy", "DeleteBucketPolicy"])
    def test_matches_policy_change_on_uploads_bucket(self, tf_resources, resource_ids, events_client, event_name):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.s3", event_name, {"bucketName": resource_ids["uploads_bucket"]})
        assert _matches(events_client, pattern, event) is True

    def test_ignores_read_only_call_on_same_bucket(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.s3", "GetBucketPolicy", {"bucketName": resource_ids["uploads_bucket"]})
        assert _matches(events_client, pattern, event) is False

    def test_ignores_policy_change_on_a_different_bucket(self, tf_resources, resource_ids, events_client):
        """The CloudTrail log bucket is a real, different bucket in this
        account -- its policy changing isn't GAP-03's concern."""
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.s3", "PutBucketPolicy", {"bucketName": resource_ids["trail_bucket"]})
        assert _matches(events_client, pattern, event) is False


class TestGap04S3VersioningSuspended:
    RULE = "gap04_s3_versioning_suspended"

    def test_matches_versioning_suspended_on_uploads_bucket(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event(
            "aws.s3", "PutBucketVersioning",
            {"bucketName": resource_ids["uploads_bucket"], "VersioningConfiguration": {"Status": "Suspended"}},
        )
        assert _matches(events_client, pattern, event) is True

    def test_ignores_versioning_reenabled_on_uploads_bucket(self, tf_resources, resource_ids, events_client):
        """The boundary case that matters: turning versioning back ON is
        the opposite of the drift this rule watches for. A pattern that
        matched on eventName alone (ignoring the nested Status) would
        wrongly alert on this -- pure noise."""
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event(
            "aws.s3", "PutBucketVersioning",
            {"bucketName": resource_ids["uploads_bucket"], "VersioningConfiguration": {"Status": "Enabled"}},
        )
        assert _matches(events_client, pattern, event) is False

    def test_ignores_versioning_suspended_on_a_different_bucket(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event(
            "aws.s3", "PutBucketVersioning",
            {"bucketName": resource_ids["trail_bucket"], "VersioningConfiguration": {"Status": "Suspended"}},
        )
        assert _matches(events_client, pattern, event) is False


class TestGap07IamPolicyChange:
    RULE = "gap07_iam_policy_change"

    @pytest.mark.parametrize("event_name", ["PutRolePolicy", "DeleteRolePolicy"])
    def test_matches_policy_change_on_lambda_role(self, tf_resources, resource_ids, events_client, event_name):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.iam", event_name, {"roleName": resource_ids["lambda_role"]})
        assert _matches(events_client, pattern, event) is True

    def test_ignores_read_only_call_on_same_role(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.iam", "GetRolePolicy", {"roleName": resource_ids["lambda_role"]})
        assert _matches(events_client, pattern, event) is False

    def test_ignores_policy_change_on_a_different_role(self, tf_resources, resource_ids, events_client):
        pattern = _pattern_for(tf_resources, self.RULE)
        event = _cloudtrail_event("aws.iam", "PutRolePolicy", {"roleName": "some-unrelated-role"})
        assert _matches(events_client, pattern, event) is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
