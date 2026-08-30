# policies/tests/gap03_s3_secure_transport_test.rego
package compliance.hipaa.s3_secure_transport_test

import rego.v1
import data.compliance.hipaa.s3_secure_transport

compliant_input := {
	"planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}}]}},
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
}

# GAP-03 re-introduced: no bucket policy at all.
missing_policy_input := {
	"planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}}]}},
	"configuration": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"}]}},
}

test_compliant_passes if {
	count(s3_secure_transport.deny) == 0 with input as compliant_input
}

test_missing_policy_fails if {
	some msg in s3_secure_transport.deny with input as missing_policy_input
	contains(msg, "164.312(e)(1)")
	contains(msg, "aws_s3_bucket.uploads")
}
