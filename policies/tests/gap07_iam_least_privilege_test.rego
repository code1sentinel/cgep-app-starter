# policies/tests/gap07_iam_least_privilege_test.rego
package compliance.hipaa.iam_least_privilege_test

import rego.v1
import data.compliance.hipaa.iam_least_privilege

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": json.marshal({"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "arn:aws:dynamodb:...:table/x"},
		{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::x/uploads/*"},
		{"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": ["arn:aws:kms:...:key/a", "arn:aws:kms:...:key/b"]},
	]})},
}]}}}

# GAP-07 fully re-introduced: the starter's original wildcard policy.
wildcard_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": json.marshal({"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:...:table/x"},
		{"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::x", "arn:aws:s3:::x/*"]},
	]})},
}]}}}

# Unresolvable at plan time: policy references not-yet-created resources.
# Real terraform show -json omits the key entirely rather than nulling it.
unresolvable_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"name": "intake-data-access"},
}]}}}

test_compliant_passes if {
	count(iam_least_privilege.deny) == 0 with input as compliant_input
	count(iam_least_privilege.warn) == 0 with input as compliant_input
}

test_wildcard_fails if {
	some msg in iam_least_privilege.deny with input as wildcard_input
	contains(msg, "164.312(a)(1)")
	contains(msg, "dynamodb:*")
}

test_unresolvable_warns_not_denies if {
	count(iam_least_privilege.deny) == 0 with input as unresolvable_input
	some msg in iam_least_privilege.warn with input as unresolvable_input
	contains(msg, "164.312(a)(1)")
}
