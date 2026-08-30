# policies/gap07_iam_least_privilege.rego
# METADATA
# title: Lambda IAM inline policy must not grant wildcard actions
# description: "Every aws_iam_role_policy must not grant a wildcard action (e.g. dynamodb:*, s3:*, or bare *) on the workload's data stores."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   severity: high
#   gap_id: GAP-07
#   remediation: "Scope the inline policy to the exact actions the Lambda handler calls (see terraform/iam_override.tf)."
#   known_limitation: "The policy JSON only resolves to a literal string in planned_values once the referenced resource ARNs are already known (an incremental plan against already-applied state, not a from-scratch first apply). When unresolvable, this policy emits a warn instead of a deny rather than failing open or closed on a guess."
package compliance.hipaa.iam_least_privilege

import rego.v1

# The starter names this policy aws_iam_role_policy.lambda_inline
# (terraform/main.tf) and GAPS.md scopes GAP-07 to it specifically.
target_policy := "aws_iam_role_policy.lambda_inline"

deny contains msg if {
	some r in all_resources("aws_iam_role_policy")
	r.address == target_policy
	policy_str := policy_value(r)
	is_string(policy_str)
	doc := json.unmarshal(policy_str)
	some stmt in as_array(doc.Statement)
	some action in as_array(stmt.Action)
	is_wildcard_action(action)
	msg := sprintf(
		"[164.312(a)(1)] %s: policy grants wildcard action %q. Remediation: scope to the exact actions the workload needs.",
		[r.address, action],
	)
}

warn contains msg if {
	some r in all_resources("aws_iam_role_policy")
	r.address == target_policy
	not is_string(policy_value(r))
	msg := sprintf(
		"[164.312(a)(1)] %s: policy value not resolvable at plan time (references not-yet-created resources). Re-run this check against an incremental plan or applied state to verify least privilege.",
		[r.address],
	)
}

# object.get supplies an explicit default when the "policy" key is entirely
# absent (as opposed to present-and-null) -- Terraform's plan JSON omits
# unresolved computed attributes rather than nulling them, and a raw
# r.values.policy lookup on a missing key is undefined, not null, which
# breaks `not is_string(...)` (negating an undefined expression stays
# undefined, it does not become true).
policy_value(r) := object.get(r.values, "policy", null)

as_array(x) := x if is_array(x)
as_array(x) := [x] if is_string(x)

is_wildcard_action(a) if endswith(a, ":*")
is_wildcard_action(a) if a == "*"

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
