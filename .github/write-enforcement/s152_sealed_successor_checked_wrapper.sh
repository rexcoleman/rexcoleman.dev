#!/usr/bin/env bash
set -euo pipefail
CANONICAL_ROOT=/data/tmp/rexdev_s152_successor_review
CANONICAL_WRAPPER=$CANONICAL_ROOT/.github/write-enforcement/s152_sealed_successor_checked_wrapper.sh
CANONICAL_HELPER=$CANONICAL_ROOT/.github/write-enforcement/s152_successor_approval_resume.py
CANONICAL_TRANSFER=$CANONICAL_ROOT/.github/write-enforcement/provision_downstream_bundle_secret.py
DEPLOYED_WRAPPER=/home/azureuser/.local/libexec/rea_enforcement/s152_sealed_successor_checked_wrapper.sh
DEPLOYED_HELPER=/home/azureuser/.local/libexec/rea_enforcement/s152_successor_approval_resume.py
DEPLOYED_TRANSFER=/home/azureuser/.local/libexec/rea_enforcement/provision_downstream_bundle_secret.py
refuse() { printf 'REFUSE(S152_SEALED_SUCCESSOR_WRAPPER): %s\n' "$1" >&2; printf 'SAFE_TO_PASTE_BACK=true secret_bytes_printed=false\n' >&2; exit 2; }
[ "$0" = "$DEPLOYED_WRAPPER" ] || refuse WRAPPER_PATH_MISMATCH
[ "$(hostname -s)" = gios-dev ] || refuse HOST_MISMATCH
[ "$(id -u)" -ne 0 ] || refuse ROOT_EXECUTION_REFUSED
[ "$#" -le 1 ] || refuse ARGUMENT_REFUSED
for path in "$CANONICAL_WRAPPER" "$CANONICAL_HELPER" "$CANONICAL_TRANSFER" "$DEPLOYED_WRAPPER" "$DEPLOYED_HELPER" "$DEPLOYED_TRANSFER"; do [ -f "$path" ] && [ ! -L "$path" ] || refuse NONREGULAR_PACKAGE_MEMBER; done
cmp -s "$DEPLOYED_WRAPPER" "$CANONICAL_WRAPPER" || refuse WRAPPER_DIGEST_MISMATCH
cmp -s "$DEPLOYED_HELPER" "$CANONICAL_HELPER" || refuse HELPER_DIGEST_MISMATCH
cmp -s "$DEPLOYED_TRANSFER" "$CANONICAL_TRANSFER" || refuse TRANSFER_DIGEST_MISMATCH
git -C "$CANONICAL_ROOT" diff --quiet HEAD -- .github/write-enforcement/s152_sealed_successor_checked_wrapper.sh .github/write-enforcement/s152_successor_approval_resume.py .github/write-enforcement/provision_downstream_bundle_secret.py || refuse CANONICAL_SOURCE_DIRTY
git -C "$CANONICAL_ROOT" merge-base --is-ancestor HEAD origin/main || refuse CANONICAL_COMMIT_NOT_PUBLISHED
export REA_S152_CHECKED_WRAPPER=rea-s152-sealed-successor-approval-v3
case "${1-}" in "") exec /usr/bin/python3 "$DEPLOYED_HELPER" ;; --preflight) exec /usr/bin/python3 "$DEPLOYED_HELPER" --preflight ;; *) refuse ARGUMENT_REFUSED ;; esac
