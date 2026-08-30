# policies/gap02_dynamodb_kms_encryption.rego
# METADATA
# title: DynamoDB submissions table must use a customer-managed key
# description: "Every aws_dynamodb_table must have server_side_encryption.enabled = true, bringing PHI records under customer-managed KMS custody rather than the AWS-owned default key."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   gap_id: GAP-02
#   remediation: "Add a server_side_encryption { enabled = true, kms_key_arn = ... } block to the table, referencing a customer-managed KMS key (see terraform/dynamodb_override.tf)."
package compliance.hipaa.dynamodb_kms_encryption

import rego.v1

# The starter names this table aws_dynamodb_table.intake (terraform/main.tf)
# and GAPS.md scopes GAP-02 to it specifically.
target_table := "aws_dynamodb_table.intake"

deny contains msg if {
	some r in all_resources("aws_dynamodb_table")
	r.address == target_table
	not has_cmk_encryption(r)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: server_side_encryption is missing or not enabled. Remediation: add server_side_encryption { enabled = true, kms_key_arn = <customer-managed key> }.",
		[r.address],
	)
}

has_cmk_encryption(r) if {
	count(r.values.server_side_encryption) > 0
	r.values.server_side_encryption[0].enabled == true
}

# --- shared helpers ----------------------------------------------------

all_resources(resource_type) := rs if {
	rs := {r |
		some r in input.planned_values.root_module.resources
		r.type == resource_type
	} | {r |
		some child in input.planned_values.root_module.child_modules
		some r in child.resources
		r.type == resource_type
	}
}
