# cgep-app-starter — Acme Health GRC Capstone

CGE-P capstone submission. Primary framework: **HIPAA Security Rule** (see [WRITEUP.md](WRITEUP.md) for why). Forks [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) — a deliberately non-compliant Patient Intake API for "Acme Health" — and wraps it with four GRC layers so the same workload becomes audit-defensible.

## What's here

| Deliverable | Where |
|---|---|
| Design decisions, trade-offs, honest gaps | [WRITEUP.md](WRITEUP.md) |
| Control-to-code mapping | [COMPLIANCE.md](COMPLIANCE.md) |
| Layer 1 — Terraform GRC baseline | `terraform/` (KMS, S3/DynamoDB overrides, CloudTrail, monitoring — see below), `terraform/evidence-vault/`, `terraform/oidc-trust/` |
| Layer 2 — OPA/Rego policy suite | `policies/` |
| Layer 3 — GitHub Actions pipeline | `.github/workflows/grc-gate.yml` |
| Layer 4 — OSCAL component | `oscal/` |
| Named gaps this closes | [GAPS.md](GAPS.md) |
| Framework primer | [FRAMEWORKS.md](FRAMEWORKS.md) |

## For the grader: verifying this submission

### 1. The gate is real, not cosmetic

Repo history has both halves of the two-PR requirement:
- **Green**: PR #1, #2, #4 — merged, full pipeline (Plan → Policy Check → Apply → Sign → Upload) succeeded each time.
- **Red**: PR #3 — deliberately reverted GAP-04 (S3 versioning). Both `policies/gap04_s3_versioning.rego` and `checkov` caught it; `gh pr merge` was refused by branch protection. Closed, not merged — see the PR for the full trace.

### 2. Verify the evidence chain yourself

Every signed pipeline run uploads to the evidence vault. Independently check any run (no need to trust this repo's word for it — this recomputes the hash and checks the signature against the public Sigstore log directly):

```bash
export EVIDENCE_VAULT=acme-health-intake-grc-evidence-vault-2f2d7f0e
export AWS_PROFILE=<your-profile-with-read-access-or-none-needed-for-cosign-step>
bash scripts/verify-evidence.sh <run_id>
# Expect: CHAIN INTACT
```

The OSCAL component (`oscal/components/acme-health-grc-baseline.json`) links each control claim to a real bundle from run `33357334981` — start there and follow the `links[rel=evidence]` hrefs. That run is a representative, fully-verified example, not a one-time snapshot: every merge to `main` produces a fresh signed bundle the same way, so `verify-evidence.sh` works against any run ID in the vault, not just this one.

### 3. Run the policy suite locally

```bash
opa test -v policies/                              # unit tests, no AWS needed
bash scripts/policy-gate.sh --workspace terraform   # live gate against a real plan (needs a saved tfplan + AWS creds)
```

### 3b. Run the test suites (IaC assertions + detection-logic pattern matching)

```bash
cd terraform && terraform test                             # plan-only, no resources created; needs AWS creds
pip install pytest boto3
pytest scripts/tests/test_detection_patterns.py -v          # needs AWS creds + a deployed terraform/ workspace
```

Both run in CI on every push/PR and block `Apply` on failure, same as checkov/gitleaks/conftest.

### 4. Validate the OSCAL

```bash
pip install compliance-trestle
trestle validate -f oscal/components/acme-health-grc-baseline.json
trestle validate -f oscal/profiles/hipaa-minimum.json
```

Both return `VALID`. See `oscal/trestle-validate.txt` for a captured run, including a documented `profile-resolve` limitation explained in `oscal/README.md`.

### 5. Deploy it yourself (optional — everything above doesn't require this)

```bash
make creds  AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
make destroy AWS_PROFILE=<your-sandbox-profile>
```

Note: `terraform/` now uses a remote S3 backend (`terraform/oidc-trust/` provisions it) rather than local state — `terraform init` needs `-backend-config` flags; see `.github/workflows/grc-gate.yml`'s "Terraform init + validate" step for the exact invocation.

## Cost

Roughly $0-1 if destroyed same-day. The evidence vault and Terraform state bucket persist intentionally (that's the point of an evidence vault); the workload itself (VPC/Lambda/API Gateway/DynamoDB/CloudTrail/monitoring) is destroyed between sessions and only briefly live during CI runs.

## Layout

```
cgep-app-starter/
├── README.md, WRITEUP.md, COMPLIANCE.md, GAPS.md, FRAMEWORKS.md, WORKLOAD.md
├── Makefile
├── .github/workflows/grc-gate.yml    # Layer 3
├── .checkov.yaml                      # justified skip list, see WRITEUP.md
├── terraform/
│   ├── main.tf, variables.tf, outputs.tf, lambda/    # the starter, unmodified
│   ├── kms.tf, s3_overrides.tf, dynamodb_override.tf,
│   │   iam_override.tf, lambda_override.tf, cloudtrail.tf,
│   │   monitoring.tf, outputs_grc.tf, backend.tf      # Layer 1 additions
│   ├── evidence-vault/                                # persistent, own state
│   └── oidc-trust/                                    # persistent, own state
├── policies/          # Layer 2: 5 Rego policies + tests
├── scripts/           # policy-gate.sh, verify-evidence.sh
├── oscal/             # Layer 4
└── test/intake.sh
```

## License

MIT.
