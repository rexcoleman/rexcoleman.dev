#!/usr/bin/env bash
set -euo pipefail
CANONICAL_ROOT=/data/tmp/rexdev_s152_v5_tombstone
CANONICAL_WRAPPER=$CANONICAL_ROOT/.github/write-enforcement/s152_ci_decoder_successor_approval_checked_wrapper.sh
CANONICAL_HELPER=$CANONICAL_ROOT/.github/write-enforcement/s152_ci_decoder_successor_approval.py
DEPLOYED_WRAPPER=/home/azureuser/.local/libexec/rea_enforcement/s152_ci_decoder_successor_approval_checked_wrapper.sh
HELPER=/home/azureuser/.local/libexec/rea_enforcement/s152_ci_decoder_successor_approval.py

refuse() {
  printf 'REFUSE(S152_CI_DECODER_SUCCESSOR_WRAPPER): %s\n' "$1" >&2
  printf 'SAFE_TO_PASTE_BACK=true secret_bytes_printed=false\n' >&2
  exit 2
}

[ "$0" = "$DEPLOYED_WRAPPER" ] || refuse WRAPPER_PATH_MISMATCH
[ "$(hostname -s)" = gios-dev ] || refuse HOST_REFUSED
[ "$(id -u)" -ne 0 ] || refuse ROOT_EXECUTION_REFUSED
[ "$#" -le 1 ] || refuse ARGUMENT_REFUSED
[ -t 0 ] && [ -t 1 ] && [ -t 2 ] || refuse OWNER_TTY_REQUIRED
for path in "$CANONICAL_WRAPPER" "$CANONICAL_HELPER" "$DEPLOYED_WRAPPER" "$HELPER"; do
  [ -f "$path" ] && [ ! -L "$path" ] || refuse NONREGULAR_PACKAGE_MEMBER
done
cmp -s "$DEPLOYED_WRAPPER" "$CANONICAL_WRAPPER" || refuse WRAPPER_DIGEST_MISMATCH
cmp -s "$HELPER" "$CANONICAL_HELPER" || refuse HELPER_DIGEST_MISMATCH
git -C "$CANONICAL_ROOT" diff --quiet HEAD -- \
  .github/write-enforcement/s152_ci_decoder_successor_approval_checked_wrapper.sh \
  .github/write-enforcement/s152_ci_decoder_successor_approval.py \
  || refuse CANONICAL_SOURCE_DIRTY
git -C "$CANONICAL_ROOT" merge-base --is-ancestor HEAD origin/main \
  || refuse CANONICAL_COMMIT_NOT_PUBLISHED
export REA_S152_CHECKED_WRAPPER=rea-s152-ci-decoder-successor-approval-v6
case "${1-}" in
  --preflight) exec /usr/bin/python3 "$HELPER" --preflight ;;
  "")
    /usr/bin/python3 "$HELPER" --preflight
    exec /usr/bin/python3 "$HELPER"
    ;;
  *) refuse ARGUMENT_REFUSED ;;
esac
