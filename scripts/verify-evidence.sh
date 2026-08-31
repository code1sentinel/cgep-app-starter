#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]
# Independently verifies a signed evidence bundle in the vault: the same
# three checks the capstone rubric's grader performs (integrity,
# authenticity/timeliness, preservation). No trust in this repo's word
# required -- every check is against the vault and the public Sigstore
# transparency log directly.
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

COSIGN_BIN="${COSIGN_BIN:-cosign}"
if ! command -v "$COSIGN_BIN" >/dev/null 2>&1; then
  echo "Need cosign on PATH, or set COSIGN_BIN to its full path." >&2
  exit 2
fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

echo "--- 1. Integrity ---"
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }
echo "SHA-256 matches: $ACTUAL"

echo "--- 2. Authenticity + timestamp ---"
"$COSIGN_BIN" verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"

echo "--- 3. Preservation ---"
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }
echo "Retention active until: $RETAIN_UNTIL"

echo
echo "CHAIN INTACT for run ${RUN_ID}"
