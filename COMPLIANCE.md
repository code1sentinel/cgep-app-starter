# COMPLIANCE.md

Control-to-code mapping for the Acme Health GRC baseline. Primary framework: **HIPAA Security Rule** (catalog cited: NIST SP 800-66 Rev. 2 — see [FRAMEWORKS.md](FRAMEWORKS.md) and [`oscal/README.md`](oscal/README.md) for why no fetchable OSCAL catalog exists for HIPAA).

Each row is one closed gap from [GAPS.md](GAPS.md), traceable across all four layers: the Terraform that fixes it, the Rego policy that continuously checks it, the monitoring rule that detects a regression in production, and the OSCAL requirement that documents it for an assessor.

| Gap | HIPAA control | Terraform (Layer 1) | Rego policy (Layer 2) | Monitoring rule (Layer 1 ext.) | OSCAL requirement (Layer 4) |
|---|---|---|---|---|---|
| **GAP-01** — S3 uploads bucket used AWS-managed SSE-S3, not a customer key | 164.312(a)(2)(iv) | `aws_s3_bucket_server_side_encryption_configuration.uploads` (`terraform/s3_overrides.tf`), CMK from `terraform/kms.tf` (`aws_kms_key.s3_data`) | `policies/gap01_s3_kms_encryption.rego` | `aws_cloudwatch_event_rule.gap01_s3_kms_key_lifecycle` (`terraform/monitoring.tf`) — alerts on `DisableKey`/`ScheduleKeyDeletion` | `hipaa-164-312-a-2-iv` in `oscal/components/acme-health-grc-baseline.json` |
| **GAP-02** — DynamoDB table used the AWS-owned default key | 164.312(a)(2)(iv) | `server_side_encryption` block merged into `aws_dynamodb_table.intake` by `terraform/dynamodb_override.tf`, CMK from `terraform/kms.tf` (`aws_kms_key.dynamodb_data`) | `policies/gap02_dynamodb_kms_encryption.rego` | `aws_cloudwatch_event_rule.gap02_dynamodb_kms_key_lifecycle` | `hipaa-164-312-a-2-iv` (second requirement, same control) |
| **GAP-03** — no bucket policy denying non-TLS requests | 164.312(e)(1) | `aws_s3_bucket_policy.uploads` (`terraform/s3_overrides.tf`) — `Deny` on `aws:SecureTransport == false` | `policies/gap03_s3_secure_transport.rego` | `aws_cloudwatch_event_rule.gap03_s3_bucket_policy_change` — alerts on `PutBucketPolicy`/`DeleteBucketPolicy` | `hipaa-164-312-e-1` |
| **GAP-04** — uploads bucket had no versioning | 164.308(a)(7) | `aws_s3_bucket_versioning.uploads` (`terraform/s3_overrides.tf`) | `policies/gap04_s3_versioning.rego` | `aws_cloudwatch_event_rule.gap04_s3_versioning_suspended` — alerts if versioning is suspended | `hipaa-164-308-a-7` |
| **GAP-07** — Lambda IAM role had `dynamodb:*`/`s3:*` | 164.312(a)(1) | Inline policy merged into `aws_iam_role_policy.lambda_inline` by `terraform/iam_override.tf`, scoped to exactly `dynamodb:PutItem`, `s3:PutObject` (under `uploads/*`), and the two CMKs' `kms:GenerateDataKey`/`kms:Decrypt` | `policies/gap07_iam_least_privilege.rego` (deny on wildcard action when resolvable; `warn` when the policy JSON can't be resolved at plan time — documented limitation, see `policies/README.md`) | `aws_cloudwatch_event_rule.gap07_iam_policy_change` — alerts on *any* touch to the policy, sidestepping the same resolution problem | `hipaa-164-312-a-1` |

## Deliberately out of scope

Per GAPS.md's own guidance ("closing five gaps with depth beats eight done thinly") and the rubric's "small and integrated beats large" framing, three gaps were left open and are documented, not silently dropped:

| Gap | HIPAA citation (GAPS.md) | What's missing | Why deferred |
|---|---|---|---|
| GAP-05 | 164.312(e)(1) — overlaps GAP-03, which *is* closed | Lambda not deployed inside the starter's VPC | Partial coverage already via GAP-03's TLS enforcement; the network-isolation angle specifically stays open. Closing it would require NAT/VPC endpoints for DynamoDB+S3 reachability from a private subnet — real added cost/complexity for a 30-day capstone |
| GAP-06 | *(none — only SOC 2 CC7.2 / CMMC SI.L2-3.14.6)* | No reserved concurrency, DLQ, or X-Ray on the Lambda | Zero cost under our declared framework. `checkov` still flags these (`CKV_AWS_116/115/50`), listed with rationale in `.checkov.yaml` |
| GAP-08 | 164.312(b) — different surface than what CloudTrail covers | No API Gateway access logging, throttling, or WAF | CloudTrail (Layer 1) covers the management plane (AWS config changes), not the data plane (who called `POST /intake`) — doesn't substitute for this one. `checkov` flags `CKV_AWS_76`/`CKV_AWS_309`, listed with rationale in `.checkov.yaml` |

## Supporting infrastructure (not gap-specific)

- **CloudTrail** (`terraform/cloudtrail.tf`) — multi-region trail, log file validation, KMS-encrypted with its own dedicated CMK. Maps to HIPAA 164.312(b) (Audit Controls).
- **Evidence vault** (`terraform/evidence-vault/`) — S3 with Object Lock (`COMPLIANCE` mode), versioned, KMS-encrypted. Where every signed pipeline bundle lands.
- **OIDC trust + remote state** (`terraform/oidc-trust/`) — the CI pipeline's AWS access (no static keys) and the shared Terraform state that makes an `Apply` step in CI possible at all.

## Automated test coverage

Two test suites run in CI on every push/PR (`.github/workflows/grc-gate.yml`), blocking `Apply` on failure like every other gate:

- **`terraform/tests/gap_fixes.tftest.hcl`** — native `terraform test`, one `run` block per GAP-01/02/03/04/07, asserting the real plan-time configuration (SSE algorithm and CMK identity, versioning status, the SecureTransport-deny statement, no wildcard IAM actions). Plan-only (`command = plan`) with `override_resource` blocks giving the cross-referenced KMS/S3/DynamoDB ARNs known values during planning — deliberately not `command = apply`, since minting a real KMS CMK just to run a test bills a full month the instant it's created, even if destroyed a second later.
- **`scripts/tests/test_detection_patterns.py`** — pytest, positive and negative cases for all 5 `monitoring.tf` EventBridge rules. Rather than reimplementing EventBridge's match semantics, it calls the real `events:TestEventPattern` API against each rule's actual deployed `event_pattern` (read live from Terraform state, so the fixtures can't drift from what's really running) and realistic CloudTrail event fixtures — including the boundary cases that matter most: the same dangerous call on a *different* real resource (proves the rule is scoped, not just present), and for GAP-04, the same event with `Status: Enabled` instead of `Suspended` (proves the rule doesn't alert on the opposite, safe transition).

## Verifying any row yourself

1. **Terraform claim** — read the cited resource in the `.tf` file; `terraform plan` against the real workspace shows it.
2. **Rego claim** — `opa test policies/` (unit tests) or `bash scripts/policy-gate.sh --workspace terraform` (live gate).
3. **Monitoring claim** — the rule exists in a deployed `terraform apply`; live-fire proof is in the Layer 1 commit message (`bacb0df`) — a real CLI-triggered drift was detected, alerted, and self-healed. `pytest scripts/tests/test_detection_patterns.py -v` gives repeatable, automated proof of the same scoping without needing to trigger a real API call.
4. **OSCAL claim** — `oscal/components/acme-health-grc-baseline.json`, validated per `oscal/trestle-validate.txt`, each `links[rel=evidence]` resolving to a real signed bundle: `bash scripts/verify-evidence.sh <run_id>` should print `CHAIN INTACT`.
