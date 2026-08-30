# policies/gap03_s3_secure_transport.rego
# METADATA
# title: S3 uploads bucket must deny non-TLS requests
# description: "Every aws_s3_bucket must have a matching aws_s3_bucket_policy wired to it, enforcing aws:SecureTransport so plaintext HTTP requests are refused."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: medium
#   gap_id: GAP-03
#   remediation: "Add an aws_s3_bucket_policy referencing the bucket with a Deny statement conditioned on aws:SecureTransport == \"false\" (see terraform/s3_overrides.tf)."
package compliance.hipaa.s3_secure_transport

import rego.v1

# Scoped to the starter's named bucket, same reasoning as gap01_s3_kms_encryption.rego.
target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	some r in all_resources("aws_s3_bucket")
	r.address == target_bucket
	not has_bucket_policy(target_bucket)
	msg := sprintf(
		"[164.312(e)(1)] %s: no aws_s3_bucket_policy found for this bucket. Remediation: add one denying requests where aws:SecureTransport is false.",
		[target_bucket],
	)
}

has_bucket_policy(bucket_addr) if {
	some r in configuration_resources("aws_s3_bucket_policy")
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
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
