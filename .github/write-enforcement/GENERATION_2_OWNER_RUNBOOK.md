# Generation-2 WEA owner runbook

This supplements, and never modifies or reruns, the generation-1 owner
package. Generation-1 key, public pins, secrets, manifest, and tag remain
untouched. Run each Part C block only when the coach presents it with exact
expected heads and stop rules.

## Required token capabilities

Create one fine-grained personal access token for the environment secret
`REA_BUNDLE_READ_TOKEN`:

- repository owner: `rexcoleman`;
- selected repositories exactly:
  `research_enforcement_activation`, `govML`,
  `Moonshots_Career_Thesis`, and `newsletter`;
- repository permissions: **Contents — Read-only**;
- every other repository and account permission: **No access**.

The existing `REA_RULESET_READ_TOKEN` is not replaced. Because the issuer
cryptographically covers `bypass_actors`, GitHub's ruleset response must include
that capability-gated field. The owner must inspect the existing fine-grained
token and confirm it selects only `newsletter` and grants
**Administration — Read and write**. GitHub requires ruleset write access to
return `bypass_actors`; the issuer still performs only an HTTP GET and fails
closed if the field is missing. Never paste either token into chat.

## Trap-safe environment-secret installation template

This block is GNU/BSD portable and does not print or persist the token:

```bash
set -euo pipefail
restore_tty() { stty echo 2>/dev/null || true; }
trap restore_tty EXIT HUP INT TERM
printf 'REA_BUNDLE_READ_TOKEN (input hidden): ' >&2
stty -echo
IFS= read -r REA_BUNDLE_TOKEN
stty echo
printf '\n' >&2
test -n "$REA_BUNDLE_TOKEN"
printf '%s' "$REA_BUNDLE_TOKEN" |
  gh secret set REA_BUNDLE_READ_TOKEN \
    --repo rexcoleman/rexcoleman.dev \
    --env rea-write-enforcement-issuer
unset REA_BUNDLE_TOKEN
trap - EXIT HUP INT TERM
gh api \
  repos/rexcoleman/rexcoleman.dev/environments/rea-write-enforcement-issuer/secrets \
  --jq '.secrets[] | [.name,.created_at,.updated_at] | @tsv' |
  LC_ALL=C sort
```

Expected metadata includes all three names and timestamps only:
`REA_BUNDLE_READ_TOKEN`, `REA_RULESET_READ_TOKEN`, and
`REA_WEA_ED25519_PRIVATE_KEY_B64`.

## Exact run discovery

Never sleep a fixed interval and never accept “latest run.” Before dispatch,
record the largest existing run ID. After dispatch, poll only for a strictly
newer run whose event, tag, and head SHA all match:

Workflow concurrency prevents overlapping issuer jobs; it does not prevent a
later duplicate issuance during the same WEA lifetime. The hand-held owner
protocol and exact baseline/run polling are the duplicate-dispatch control.

```bash
set -euo pipefail
ISSUER_REPO=rexcoleman/rexcoleman.dev
ISSUER_SHA='REPLACE_WITH_VERIFIED_40_HEX_MANIFEST_COMMIT'
ISSUER_TAG="rea-wea-generation-2-$(printf '%s' "$ISSUER_SHA" | cut -c1-12)"
test "${#ISSUER_SHA}" -eq 40
case "$ISSUER_SHA" in *[!0-9a-f]*) exit 3 ;; esac
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

The required-reviewers pause is expected. On any head/tag/event mismatch,
missing pending deployment, failed self-check, or unexpected output: stop and
paste raw output to the coach. Do not improvise around frozen bytes. After
approval, the coach uses a Python `hashlib.sha256` checksum check, not
platform-specific `sha256sum`, for owner-downloaded artifacts.
