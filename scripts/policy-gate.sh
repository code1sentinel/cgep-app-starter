#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
# CI (Layer 3) calls this directly as the Policy Check step, between Plan and Apply.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_FILE="policy-gate-results.json"
CONFTEST_BIN="${CONFTEST_BIN:-conftest}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }

# Write plan.json next to tfplan. Use -chdir so a relative WORKSPACE path
# doesn't get doubled after a cd (a common bash footgun).
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

# One namespace per gap-closing policy in policies/. Keep in sync with the
# `package compliance.hipaa.*` declarations.
NAMESPACES=(
  compliance.hipaa.s3_kms_encryption
  compliance.hipaa.dynamodb_kms_encryption
  compliance.hipaa.s3_secure_transport
  compliance.hipaa.s3_versioning
  compliance.hipaa.iam_least_privilege
)

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Capture JSON even when conftest exits non-zero; use that exit code for the gate.
    set +e
    OUT=$("$CONFTEST_BIN" test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_FILE"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_FILE"
fi
exit $EXIT
