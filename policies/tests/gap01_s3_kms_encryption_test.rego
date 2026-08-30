# policies/tests/gap01_s3_kms_encryption_test.rego
package compliance.hipaa.s3_kms_encryption_test

import rego.v1
import data.compliance.hipaa.s3_kms_encryption

compliant_input := {
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
		},
	]}},
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
}

# GAP-01 re-introduced: SSE config present but still AES256 (the AWS default), not aws:kms.
wrong_algorithm_input := {
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
		},
	]}},
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
}

# GAP-01 fully re-introduced: no encryption configuration resource at all.
missing_config_input := {
	"planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}}]}},
	"configuration": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"}]}},
}

test_compliant_passes if {
	count(s3_kms_encryption.deny) == 0 with input as compliant_input
}

test_wrong_algorithm_fails if {
	some msg in s3_kms_encryption.deny with input as wrong_algorithm_input
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_s3_bucket.uploads")
}

test_missing_config_fails if {
	some msg in s3_kms_encryption.deny with input as missing_config_input
	contains(msg, "164.312(a)(2)(iv)")
}
