# policies/tests/gap04_s3_versioning_test.rego
package compliance.hipaa.s3_versioning_test

import rego.v1
import data.compliance.hipaa.s3_versioning

compliant_input := {
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"values": {"versioning_configuration": [{"status": "Enabled"}]},
		},
	]}},
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
}

# GAP-04 re-introduced: versioning resource present but suspended, not enabled.
suspended_input := {
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"values": {"versioning_configuration": [{"status": "Suspended"}]},
		},
	]}},
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
}

# GAP-04 fully re-introduced: no versioning resource at all (the starter's original shape).
missing_input := {
	"planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "values": {}}]}},
	"configuration": {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads"}]}},
}

test_compliant_passes if {
	count(s3_versioning.deny) == 0 with input as compliant_input
}

test_suspended_fails if {
	some msg in s3_versioning.deny with input as suspended_input
	contains(msg, "164.308(a)(7)")
}

test_missing_fails if {
	some msg in s3_versioning.deny with input as missing_input
	contains(msg, "164.308(a)(7)")
	contains(msg, "aws_s3_bucket.uploads")
}
