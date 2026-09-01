#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
TOOL=$REPOSITORY/.github/write-enforcement/setup_external_judge_hosted_principal.py
if [[ ! -f "$TOOL" || -L "$TOOL" ]]; then
  printf 'HOSTED_PRINCIPAL_SETUP_REFUSED reason=CHECKED_TOOL_ABSENT path=%s\n' "$TOOL"
  exit 3
fi
REMOTE=$(/usr/bin/git -C "$REPOSITORY" ls-remote origin refs/heads/main)
read -r COMMIT REF TRAILING <<<"$REMOTE"
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ || "$REF" != refs/heads/main || -n "${TRAILING:-}" ]]; then
  printf 'HOSTED_PRINCIPAL_SETUP_REFUSED reason=REX_PAYLOAD_COMMIT_REFUSED\n'
  exit 3
fi
if [[ "$(/usr/bin/git -C "$REPOSITORY" rev-parse HEAD)" != "$COMMIT" ]]; then
  printf 'HOSTED_PRINCIPAL_SETUP_REFUSED reason=REX_PAYLOAD_HEAD_REFUSED\n'
  exit 3
fi
PAYLOAD=(
  .github/write-enforcement/setup_external_judge_hosted_principal.py
  .github/write-enforcement/setup_external_judge_hosted_principal.sh
  .github/write-enforcement/rea_s169_external_judge_principal_owner_row.txt
)
if [[ -n "$(/usr/bin/git -C "$REPOSITORY" status --porcelain -- "${PAYLOAD[@]}")" ]]; then
  printf 'HOSTED_PRINCIPAL_SETUP_REFUSED reason=REX_PAYLOAD_DIRTY_REFUSED\n'
  exit 3
fi
if ! /usr/bin/git -C "$REPOSITORY" diff --quiet "$COMMIT" -- "${PAYLOAD[@]}"; then
  printf 'HOSTED_PRINCIPAL_SETUP_REFUSED reason=REX_PAYLOAD_BYTES_REFUSED\n'
  exit 3
fi
exec /usr/bin/python3 "$TOOL" --apply
