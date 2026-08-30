# policies/gap01_s3_kms_encryption.rego
# METADATA
# title: S3 uploads bucket must use SSE-KMS with a customer-managed key
# description: "Every aws_s3_bucket must have a matching aws_s3_bucket_server_side_encryption_configuration whose sse_algorithm is aws:kms (not AWS-managed SSE-S3)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   gap_id: GAP-01
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration referencing the bucket, with apply_server_side_encryption_by_default.sse_algorithm = \"aws:kms\" and kms_master_key_id set to a customer-managed KMS key."
package compliance.hipaa.s3_kms_encryption

import rego.v1

# The starter names this bucket aws_s3_bucket.uploads (terraform/main.tf) and
# GAPS.md scopes GAP-01 to it specifically. Matching only this address (not
# every aws_s3_bucket in the plan) avoids false positives on unrelated
# buckets this capstone also provisions, e.g. the CloudTrail bucket.
target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	some r in all_resources("aws_s3_bucket")
	r.address == target_bucket
	not has_kms_encryption(target_bucket)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: no aws_s3_bucket_server_side_encryption_configuration using aws:kms found for this bucket. Remediation: add one referencing a customer-managed KMS key.",
		[target_bucket],
	)
}

has_kms_encryption(bucket_addr) if {
	some r in configuration_resources("aws_s3_bucket_server_side_encryption_configuration")
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	planned := planned_values_for(sprintf("aws_s3_bucket_server_side_encryption_configuration.%s", [r.name]))
	some rule in planned.rule
	some default_rule in rule.apply_server_side_encryption_by_default
	default_rule.sse_algorithm == "aws:kms"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

# --- shared helpers (same shape in every gap policy) -----------------

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

configuration_resources(resource_type) := rs if {
	rs := {r |
		some r in input.configuration.root_module.resources
		r.type == resource_type
	}
}

planned_values_for(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
