# policies/gap04_s3_versioning.rego
# METADATA
# title: S3 uploads bucket must have versioning enabled
# description: "Every aws_s3_bucket must have a matching aws_s3_bucket_versioning resource with status Enabled, so overwritten or deleted PHI attachments remain recoverable."
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   gap_id: GAP-04
#   remediation: "Add an aws_s3_bucket_versioning resource referencing the bucket with versioning_configuration { status = \"Enabled\" } (see terraform/s3_overrides.tf)."
package compliance.hipaa.s3_versioning

import rego.v1

# Scoped to the starter's named bucket, same reasoning as gap01_s3_kms_encryption.rego.
target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	some r in all_resources("aws_s3_bucket")
	r.address == target_bucket
	not has_versioning_enabled(target_bucket)
	msg := sprintf(
		"[164.308(a)(7)] %s: no aws_s3_bucket_versioning with status=Enabled found for this bucket. Remediation: add one referencing this bucket.",
		[target_bucket],
	)
}

has_versioning_enabled(bucket_addr) if {
	some r in configuration_resources("aws_s3_bucket_versioning")
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	planned := planned_values_for(sprintf("aws_s3_bucket_versioning.%s", [r.name]))
	some vc in planned.versioning_configuration
	vc.status == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

# --- shared helpers ------------------------------------------------

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
