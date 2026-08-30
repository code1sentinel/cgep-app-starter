# policies/tests/gap02_dynamodb_kms_encryption_test.rego
package compliance.hipaa.dynamodb_kms_encryption_test

import rego.v1
import data.compliance.hipaa.dynamodb_kms_encryption

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": null}]},
}]}}}

# GAP-02 re-introduced: block entirely absent (the starter's original shape).
missing_block_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"server_side_encryption": []},
}]}}}

# GAP-02 partially re-introduced: block present but disabled.
disabled_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"server_side_encryption": [{"enabled": false}]},
}]}}}

test_compliant_passes if {
	count(dynamodb_kms_encryption.deny) == 0 with input as compliant_input
}

test_missing_block_fails if {
	some msg in dynamodb_kms_encryption.deny with input as missing_block_input
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_dynamodb_table.intake")
}

test_disabled_fails if {
	some msg in dynamodb_kms_encryption.deny with input as disabled_input
	contains(msg, "164.312(a)(2)(iv)")
}
