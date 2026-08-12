#!/usr/bin/env bash
set -euo pipefail
CANONICAL_ROOT=/data/tmp/rexdev_s152_auth_owner
CANONICAL_WRAPPER=$CANONICAL_ROOT/.github/write-enforcement/s152_ci_git_auth_successor_approval_v8_checked_wrapper.sh
CANONICAL_HELPER=$CANONICAL_ROOT/.github/write-enforcement/s152_ci_git_auth_successor_approval_v8.py
CANONICAL_BASE=$CANONICAL_ROOT/.github/write-enforcement/s152_ci_decoder_successor_approval_v7.py
DEPLOYED_WRAPPER=/home/azureuser/.local/libexec/rea_enforcement/s152_ci_git_auth_successor_approval_v8_checked_wrapper.sh
HELPER=/home/azureuser/.local/libexec/rea_enforcement/s152_ci_git_auth_successor_approval_v8.py
BASE=/home/azureuser/.local/libexec/rea_enforcement/s152_ci_decoder_successor_approval_v7.py

refuse() {
  printf 'REFUSE(S152_CI_GIT_AUTH_SUCCESSOR_V8_WRAPPER): %s\n' "$1" >&2
  printf 'SAFE_TO_PASTE_BACK=true secret_bytes_printed=false\n' >&2
  exit 2
}

[ "$0" = "$DEPLOYED_WRAPPER" ] || refuse WRAPPER_PATH_MISMATCH
[ "$(hostname -s)" = gios-dev ] || refuse HOST_REFUSED
[ "$(id -u)" -ne 0 ] || refuse ROOT_EXECUTION_REFUSED
[ "$#" -le 1 ] || refuse ARGUMENT_REFUSED
[ -t 0 ] && [ -t 1 ] && [ -t 2 ] || refuse OWNER_TTY_REQUIRED
for path in "$CANONICAL_WRAPPER" "$CANONICAL_HELPER" "$CANONICAL_BASE" "$DEPLOYED_WRAPPER" "$HELPER" "$BASE"; do
  [ -f "$path" ] && [ ! -L "$path" ] || refuse NONREGULAR_PACKAGE_MEMBER
done
cmp -s "$DEPLOYED_WRAPPER" "$CANONICAL_WRAPPER" || refuse WRAPPER_DIGEST_MISMATCH
cmp -s "$HELPER" "$CANONICAL_HELPER" || refuse HELPER_DIGEST_MISMATCH
cmp -s "$BASE" "$CANONICAL_BASE" || refuse BASE_DIGEST_MISMATCH
git -C "$CANONICAL_ROOT" diff --quiet HEAD -- \
  .github/write-enforcement/s152_ci_git_auth_successor_approval_v8_checked_wrapper.sh \
  .github/write-enforcement/s152_ci_git_auth_successor_approval_v8.py \
  .github/write-enforcement/s152_ci_decoder_successor_approval_v7.py \
  || refuse CANONICAL_SOURCE_DIRTY
git -C "$CANONICAL_ROOT" merge-base --is-ancestor HEAD origin/main \
  || refuse CANONICAL_COMMIT_NOT_PUBLISHED
export REA_S152_CHECKED_WRAPPER=rea-s152-ci-git-auth-successor-approval-v8
case "${1-}" in
  --preflight) exec /usr/bin/python3 "$HELPER" --preflight ;;
  "")
    /usr/bin/python3 "$HELPER" --preflight
    exec /usr/bin/python3 "$HELPER"
    ;;
  *) refuse ARGUMENT_REFUSED ;;
esac
