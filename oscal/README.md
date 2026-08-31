# OSCAL — Layer 4

## What's here

- **`components/acme-health-grc-baseline.json`** — one component definition describing the GRC baseline this capstone wraps around the inherited `cgep-app-starter` workload (Layer 1's Terraform overrides). Five `implemented-requirements`, one per closed gap (GAP-01, 02, 03, 04, 07), each citing a HIPAA `164.x` control, the exact Terraform resource that enforces it, the Rego policy that continuously checks it, and a real evidence link into the vault.
- **`profiles/hipaa-minimum.json`** — selects those five citations from the declared framework.
- **`trestle-validate.txt`** — captured output of `trestle validate` on both files (both `VALID`), plus a documented `profile-resolve` attempt.

## The HIPAA/OSCAL catalog limitation

NIST publishes no machine-readable OSCAL catalog for the HIPAA Security Rule (confirmed against [`usnistgov/oscal-content`](https://github.com/usnistgov/oscal-content), which covers only CSF, SP800-171, SP800-172, SP800-218, and SP800-53 — no SP800-66). Per `FRAMEWORKS.md`'s own guidance, `control-implementation.source` cites NIST SP 800-66 Rev. 2's real publication URL, and `control-id` values are slugified `164.x` citations (prefixed with `hipaa-` since OSCAL tokens can't start with a digit) rather than references into a resolvable catalog — the literal citation is repeated in each requirement's `hipaa-citation` prop.

One consequence: `trestle author profile-resolve` fails against `hipaa-minimum.json`, because there's no real OSCAL JSON behind the SP 800-66 URL for it to fetch and resolve. This is captured verbatim in `trestle-validate.txt` rather than hidden — `trestle validate` (schema-only, no network fetch) is the actual bar both documents meet, and did.

## Verifying the evidence chain yourself

Every `implemented-requirement` links to the same signed pipeline bundle (run `33357334981`, the most recent successful Layer 3 merge). Verify it independently:

```bash
export EVIDENCE_VAULT=acme-health-intake-grc-evidence-vault-2f2d7f0e
export AWS_PROFILE=cgep-sandbox
bash scripts/verify-evidence.sh 33357334981
```

Expect `CHAIN INTACT` — SHA-256 match, `cosign verify-blob` against the public Sigstore log, and Object Lock retention all confirmed independently of anything this repo claims.
