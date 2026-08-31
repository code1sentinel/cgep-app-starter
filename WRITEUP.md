# WRITEUP.md

**Primary framework: HIPAA Security Rule.** The workload is a patient-intake API handling PHI (patient ID, submitted fields, optional file attachments), so HIPAA's Technical Safeguards are the most direct fit among the three options FRAMEWORKS.md offers. NIST SP 800-66 Rev. 2 is cited as the implementation guide (there is no official NIST OSCAL catalog for HIPAA itself — see the OSCAL section below).

## Design decisions

### Why five gaps, not eight

GAPS.md is explicit that five gaps closed with depth beats eight closed thinly ("closing five gaps with depth and clear OSCAL traceability is what passes"), and the capstone brief repeats the same warning against the opposite mistake ("a small Terraform that closes five gaps cleanly beats a large Terraform that adds new resources without governing the starter"). GAP-01, 02, 03, 04, and 07 were chosen because they're the direct PHI-custody and access-control issues — encryption at rest, transmission security, and least privilege are the load-bearing HIPAA technical safeguards for this workload.

The three deferred gaps don't carry equal weight, and it's worth being precise rather than lumping them together:

- **GAP-06** (no reserved concurrency/DLQ/X-Ray on the Lambda) carries **no HIPAA citation at all** in GAPS.md's own gap table — only SOC 2 CC7.2 and CMMC SI.L2-3.14.6 are listed. Deferring it costs nothing under our declared primary framework.
- **GAP-05** (Lambda not deployed inside the starter's VPC) *does* carry a real HIPAA citation — 164.312(e)(1), Transmission Security — the same control GAP-03 addresses (the SecureTransport-deny policy). So there's partial coverage already; what stays open is specifically the network-isolation angle, and closing it would have required standing up NAT gateways or VPC endpoints just to keep the Lambda able to reach DynamoDB/S3 from a private subnet — real cost and complexity disproportionate to a 30-day capstone.
- **GAP-08** (no API Gateway access logging/throttling/WAF) also carries a real citation — 164.312(b), Audit Controls. CloudTrail (built in Layer 1) gives us audit coverage at the *management plane* (who changed AWS configuration), but that's a different surface from the *data plane* (who actually called `POST /intake` and with what payload) — CloudTrail doesn't substitute for this one, and it stays honestly open.

All three are documented with this same precision in `.checkov.yaml` and `COMPLIANCE.md`, not silently dropped or flattened into one vague "operational, lower severity" bucket.

### Additive files over editing the starter

Every Layer 1 fix is a new `.tf` file, not an edit to `main.tf`. Two of the five gaps (GAP-02's DynamoDB encryption, GAP-07's IAM policy) are attributes *inside* resource blocks the starter already defines, not separate resource types — those use Terraform's native `*_override.tf` mechanism, which merges into an existing resource block by type+name without touching the original file. The result: `git diff` against the starter shows only additions, and the starter's own resources stay exactly as shipped, satisfying the submission checklist's "the starter's resources are still present and runnable."

### Reuse over new resources

The evidence vault (`terraform/evidence-vault/`) is Lab 2.5's vault, unchanged in shape. `scripts/policy-gate.sh` from Layer 2 is called directly by the CI pipeline's Policy Check step, not reimplemented. CloudTrail delivers to its own dedicated bucket rather than a second vault-adjacent bucket. Each of these was a deliberate call to keep the system small and integrated rather than adding parallel infrastructure that does almost the same thing.

### Continuous monitoring: CloudTrail → EventBridge → SNS, not AWS Config

The rubric's "Continuous Monitoring & Detection" dimension (10%) isn't covered by any of the four course layers — it surfaced only after reading the actual grading rubric PDF, not the lab guides. The first design (AWS Config with per-gap managed rules) was replaced after checking how a further-along public capstone fork had solved the same problem: CloudTrail-sourced EventBridge rules watching for the *specific dangerous API call* that would re-open each gap, routed to SNS with an SQS dead-letter queue. This is cheaper (reuses CloudTrail, no Config recorder cost), more certain (no dependency on guessing exact AWS-managed Config rule IDs), and for GAP-07 specifically it sidesteps content-parsing entirely — instead of trying to detect a wildcard *inside* an IAM policy, it alerts whenever the policy is touched *at all*, which is unambiguous regardless of Terraform plan/state timing. This was tested live: a manual `aws s3api put-bucket-versioning ... Status=Suspended` call was detected by CloudTrail, the matching EventBridge rule fired exactly once (confirmed via CloudWatch metrics), the SNS alert arrived by email, and a subsequent `terraform apply` reverted the drift automatically.

### Least-privilege CI role, built by iteration

The GitHub Actions pipeline's AWS role (`terraform/oidc-trust/`) was hand-written to the exact permissions expected, rather than a broad managed policy — matching the least-privilege ethos GAP-07 established for the Lambda's own role. Getting a hand-scoped IAM policy exactly right on paper isn't realistic; it converged through **nine rounds** of real `AccessDenied` errors from actual `terraform apply` runs in CI, each fixed and re-run. Real findings, not guessed: `s3:GetBucketAcl`/`CORS`/`Website`/etc. (the AWS provider reads a whole set of S3 sub-resource attributes regardless of whether the config uses them), `kms:CreateGrant` (DynamoDB creates an internal grant on the caller's behalf), several actions that don't support resource-level IAM scoping at all (`kms:ListAliases`, `cloudtrail:DescribeTrails`) and needed `Resource: "*"`, and one KMS-alias-naming inconsistency between `kms.tf`'s literal alias names and the IAM policy's assumed naming convention.

## A real platform discovery: GitHub's immutable OIDC identity

The OIDC trust between GitHub and AWS initially failed every attempt with "Not authorized to perform sts:AssumeRoleWithWebIdentity" despite the trust policy, OIDC provider, and thumbprint all matching Lab 4.3's documented pattern exactly. Rather than keep guessing, a temporary debug step was added to the workflow to decode and print the actual OIDC token's claims. The real `sub` claim was `repo:code1sentinel@228478940/cgep-app-starter@1345892945:pull_request` — GitHub now embeds immutable numeric organization/repo IDs into the token (so trust survives a rename), not the plain `repo:OWNER/REPO:*` format the lab's guide (written before this) assumes. The fix — pinning the trust condition to the numeric IDs — is actually *stronger* than the documented pattern: it doesn't silently re-attach if the repo were ever deleted and recreated under the same name. The debug step was removed once confirmed; the discovery and reasoning are preserved in the commit message (`terraform/oidc-trust` history).

## The two-PR proof

Two real PRs merged with the full pipeline succeeding end-to-end (Plan → Policy Check → Apply → Sign → Upload), confirming reproducibility rather than a one-off. A third PR deliberately re-introduced GAP-04 (removed S3 versioning): both `gap04_s3_versioning.rego` and `checkov` independently flagged it, and `gh pr merge` was refused outright by branch protection ("the base branch policy prohibits the merge") — not just a red status badge nobody enforces.

## The HIPAA/OSCAL catalog gap

NIST publishes no machine-readable OSCAL catalog for HIPAA/SP 800-66 — confirmed directly against `usnistgov/oscal-content`, which covers only CSF, SP800-171, SP800-172, SP800-218, and SP800-53. `control-implementation.source` in the OSCAL component cites the real SP 800-66 Rev. 2 publication URL per FRAMEWORKS.md's own guidance, and `control-id` values are slugified HIPAA citations rather than references into a resolvable catalog. One direct consequence: `trestle author profile-resolve` fails against `oscal/profiles/hipaa-minimum.json`, because there's no real catalog JSON behind that URL to fetch. This is captured verbatim in `oscal/trestle-validate.txt` and explained in `oscal/README.md` rather than hidden. `trestle validate` (schema-only, no network fetch) is the actual bar both OSCAL documents meet, and do.

## Trade-offs accepted

- **GAP-07's Rego check is existence/warn-based when unresolvable, not always content-based.** The inline IAM policy JSON only resolves to a literal string in `terraform show -json`'s `planned_values` once every ARN it references already exists — an incremental plan against already-applied state, the realistic CI scenario (PRs plan against `main`'s existing infrastructure), not a from-scratch first apply. The policy distinguishes this explicitly: `deny` when resolvable and a wildcard is found, `warn` (non-blocking) when unresolvable, rather than silently passing or guessing. Verified live on both paths.
- **Checkov findings are suppressed with individual, dated justification, not blanket-ignored.** `.checkov.yaml` lists 20 check IDs, each with a one-line reason: deferred gaps (GAP-05/06/08), generic S3/DR hygiene outside this capstone's scope (cross-region replication, event notifications, lifecycle config — would need real added infrastructure), the CI role's necessarily-broad `Resource: "*"` statements (AWS's own IAM constraint, not a shortcut), and two cases where checkov's static HCL scan can't see a fix that's genuinely applied through an override file.
- **Single AWS account, not a separate evidence-vault account.** Acceptable for a 30-day capstone per the brief's own stated trade-off list; a real production system would separate them.
- **`COMPLIANCE` mode Object Lock from day one**, not `GOVERNANCE`-then-tighten. Chosen deliberately with a short 1-day default retention specifically so test uploads during Layer 3 development wouldn't sit undeletable for a long period by mistake — real evidence gets a longer retention set explicitly.

## What we didn't get to

- GAP-05, GAP-06, GAP-08 remain open (documented above and in `.checkov.yaml`/`COMPLIANCE.md`), along with a corresponding custom Config-style detection for GAP-07's content (only existence-based detection was built for it in Layer 1's monitoring extension).
- No Security Hub / AWS Config integration — deliberately skipped in favor of the cheaper, more targeted CloudTrail→EventBridge pattern (see above), but Security Hub's broader NIST 800-53/FSBP account-wide coverage was never built.
- The KMS alias naming inconsistency (`acme-health-*` vs. the `${var.project_name}-*` convention used everywhere else) was patched around in the CI role's IAM policy rather than fixed at the source, to avoid a destroy/recreate on already-applied aliases mid-build.
- No System Security Plan (SSP) — explicitly a capstone stretch goal per Lab 6.1, not attempted.
- `tfsec`/Trivy were not added alongside `checkov`; the rubric names `checkov` and `gitleaks` specifically as Tier-0 tools, and adding a second overlapping IaC scanner was judged to add noise rather than coverage for the time available.
