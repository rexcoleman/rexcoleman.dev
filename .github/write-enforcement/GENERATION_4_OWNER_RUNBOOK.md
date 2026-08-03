# Generation-4 WEA owner runbook

This supplements and never modifies or reruns earlier generation owner
material. Generation 4 is successor-based: active issuance names the protected
workflow run containing the exact authenticated WEA currently installed. The
read-only lifecycle preflight authenticates and binds its digest; the issuer
independently recomputes that digest and derives the adjacent successor epoch.

## Frozen identity

After the manifest-only freeze commit, derive rather than invent:

```bash
set -euo pipefail
ISSUER_SHA='REPLACE_WITH_VERIFIED_40_LOWERCASE_HEX_MANIFEST_COMMIT'
test "${#ISSUER_SHA}" -eq 40
case "$ISSUER_SHA" in *[!0-9a-f]*) exit 3 ;; esac
ISSUER_TAG="rea-wea-generation-4-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
printf 'ISSUER_SHA=%s\nISSUER_TAG=%s\n' "$ISSUER_SHA" "$ISSUER_TAG"
```

The owner independently verifies that `ISSUER_SHA` is the exact pushed
manifest commit, that its stat names only
`.github/write-enforcement/frozen_bundle_manifest.generation-4.json`, and that
the active tag ruleset covers the exact full ref. Stop on any mismatch.

## Active successor dispatch

Before dispatch, record the largest existing run ID and the current installed
WEA's `workflow_run_id` from its authenticated issuance receipt:

```bash
set -euo pipefail
ISSUER_REPO=rexcoleman/rexcoleman.dev
ISSUER_SHA='REPLACE_WITH_VERIFIED_40_LOWERCASE_HEX_MANIFEST_COMMIT'
PREDECESSOR_RUN_ID='REPLACE_WITH_CURRENT_INSTALLED_WEA_WORKFLOW_RUN_ID'
PREDECESSOR_WEA_PATH=/home/azureuser/.local/state/rea_enforcement/remote_wea/write_enforcement_attestation.json
test -f "$PREDECESSOR_WEA_PATH" && test ! -L "$PREDECESSOR_WEA_PATH"
PREDECESSOR_WEA_SHA256="$(sha256sum "$PREDECESSOR_WEA_PATH" | cut -d' ' -f1)"
test "${#ISSUER_SHA}" -eq 40
case "$ISSUER_SHA$PREDECESSOR_RUN_ID" in *[!0-9]*) exit 3 ;; esac
ISSUER_TAG="rea-wea-generation-4-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
BASELINE_RUN_ID="$(
  gh api "repos/$ISSUER_REPO/actions/workflows/issue-write-enforcement-attestation.yml/runs?per_page=1" \
    --jq '.workflow_runs[0].id // 0'
)"
gh workflow run issue-write-enforcement-attestation.yml \
  --repo "$ISSUER_REPO" --ref "$ISSUER_TAG" \
  -f predecessor_run_id="$PREDECESSOR_RUN_ID" \
  -f predecessor_wea_sha256="$PREDECESSOR_WEA_SHA256"
```

Poll only for a strictly newer workflow-dispatch run whose tag and head SHA
match `ISSUER_TAG` and `ISSUER_SHA`. The required-reviewer pause is expected.
On any head/tag/event mismatch, missing pending deployment, failed self-check,
or unexpected output: stop and preserve raw output without secret values.

The green run must show checksum verification, hosted WEA self-verification,
and artifact upload all executed successfully. It does not itself run R4 or
re-arm the write side.
