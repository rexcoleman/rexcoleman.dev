# Generation-3 WEA owner runbook

This supplements and never modifies or reruns the generation-1 or generation-2
owner material. The existing environment, signing key, public-key pins,
generation-1/generation-2 manifests, tags, and three generation-2-proven secret
names remain untouched. Run each owner block only when the coach presents it
with exact expected heads and stop rules.

Generation 3 is the final authorized cut without kernel-coach reassessment. A
deterministic content failure is terminal; do not create or propose generation
4.

## Frozen identity

After the manifest-only freeze commit, derive rather than invent:

```bash
set -euo pipefail
ISSUER_SHA='REPLACE_WITH_VERIFIED_40_LOWERCASE_HEX_MANIFEST_COMMIT'
test "${#ISSUER_SHA}" -eq 40
case "$ISSUER_SHA" in *[!0-9a-f]*) exit 3 ;; esac
ISSUER_TAG="rea-wea-generation-3-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
printf 'ISSUER_SHA=%s\nISSUER_TAG=%s\n' "$ISSUER_SHA" "$ISSUER_TAG"
```

The owner independently verifies that `ISSUER_SHA` is the pushed
`s81-remote-wea-work` head, that its stat names only
`.github/write-enforcement/frozen_bundle_manifest.generation-3.json`, and that
the existing active tag ruleset covers the exact full ref. The owner then
creates the protected annotated tag. Stop on any mismatch.

## Exact run discovery

Never sleep a fixed interval and never accept “latest run.” Before dispatch,
record the largest existing run ID. After dispatch, poll only for a strictly
newer run whose event, tag, and head SHA all match:

```bash
set -euo pipefail
ISSUER_REPO=rexcoleman/rexcoleman.dev
ISSUER_SHA='REPLACE_WITH_VERIFIED_40_LOWERCASE_HEX_MANIFEST_COMMIT'
test "${#ISSUER_SHA}" -eq 40
case "$ISSUER_SHA" in *[!0-9a-f]*) exit 3 ;; esac
ISSUER_TAG="rea-wea-generation-3-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
BASELINE_RUN_ID="$(
  gh api "repos/$ISSUER_REPO/actions/workflows/issue-write-enforcement-attestation.yml/runs?per_page=1" \
    --jq '.workflow_runs[0].id // 0'
)"
gh workflow run issue-write-enforcement-attestation.yml \
  --repo "$ISSUER_REPO" --ref "$ISSUER_TAG" -f time_mode=active
RUN_ID=
attempt=0
while [ "$attempt" -lt 60 ]; do
  RUN_ID="$(
    gh api "repos/$ISSUER_REPO/actions/workflows/issue-write-enforcement-attestation.yml/runs?event=workflow_dispatch&branch=$ISSUER_TAG&per_page=20" \
      --jq '[.workflow_runs[] | select(.id > '"$BASELINE_RUN_ID"' and .event=="workflow_dispatch" and .head_branch=="'"$ISSUER_TAG"'" and .head_sha=="'"$ISSUER_SHA"'")] | sort_by(.id) | .[0].id // empty'
  )"
  [ -n "$RUN_ID" ] && break
  attempt=$((attempt + 1))
  sleep 2
done
test -n "$RUN_ID"
gh run view "$RUN_ID" --repo "$ISSUER_REPO" \
  --json databaseId,event,headBranch,headSha,status,conclusion
```

The required-reviewer pause is expected. Approval is a separate owner step.
On any head/tag/event mismatch, missing pending deployment, failed self-check,
or unexpected output: stop and paste raw output without secret values.

The green run must show checksum verification, hosted WEA self-verification,
and artifact upload all executed successfully. Only after that green result may
the owner revoke the old metadata-only ruleset token. The write-tier token
currently installed under `REA_RULESET_READ_TOKEN` remains.
