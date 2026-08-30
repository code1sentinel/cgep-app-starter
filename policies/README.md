# Policy suite

Five Rego policies enforcing the primary framework declared for this capstone: **HIPAA Security Rule**. Each closes one named gap from [`GAPS.md`](../GAPS.md) and is enforced by `scripts/policy-gate.sh` (Conftest) against `terraform/`'s plan output.

| Policy | Gap | Control | Severity | Remediation |
|---|---|---|---|---|
| `gap01_s3_kms_encryption.rego` | GAP-01 | 164.312(a)(2)(iv) | high | Add `aws_s3_bucket_server_side_encryption_configuration` with `sse_algorithm = "aws:kms"` referencing a customer-managed key. |
| `gap02_dynamodb_kms_encryption.rego` | GAP-02 | 164.312(a)(2)(iv) | high | Add `server_side_encryption { enabled = true, kms_key_arn = ... }` to the table. |
| `gap03_s3_secure_transport.rego` | GAP-03 | 164.312(e)(1) | medium | Add an `aws_s3_bucket_policy` denying requests where `aws:SecureTransport` is `false`. |
| `gap04_s3_versioning.rego` | GAP-04 | 164.308(a)(7) | medium | Add `aws_s3_bucket_versioning` with `status = "Enabled"`. |
| `gap07_iam_least_privilege.rego` | GAP-07 | 164.312(a)(1) | high | Scope the inline IAM policy to exact actions instead of `service:*`. |

## Known limitation: GAP-07

`gap07_iam_least_privilege.rego`'s check is content-dependent — it parses the IAM policy JSON and looks for a wildcard action. That JSON only resolves to a literal string in `terraform show -json`'s `planned_values` once every ARN it references is already known, i.e. an **incremental** plan against already-applied state. On a from-scratch first apply (all referenced resources being created in the same plan), the value is `null` at plan time and the policy can't be evaluated.

Rather than silently pass or guess, the policy distinguishes the two cases explicitly:
- **Resolvable + wildcard found → `deny`** (blocks the gate).
- **Unresolvable → `warn`** (visible, non-blocking) explaining that verification needs a plan against existing state.

In the real Layer 3 CI pipeline, PRs plan against `main`'s already-applied infrastructure, so this resolves correctly in practice — this limitation only shows up on a genuinely fresh, empty-account apply.

## Running the suite

```bash
opa test -v policies/                          # unit tests, hand-built fixtures, no AWS needed
bash scripts/policy-gate.sh --workspace terraform   # live gate against the real plan
```
