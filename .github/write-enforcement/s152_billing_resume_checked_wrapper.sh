#!/usr/bin/env bash
set -euo pipefail

CANONICAL_ROOT=/data/tmp/rexdev_s152_billing_arc
CANONICAL_WRAPPER=$CANONICAL_ROOT/.github/write-enforcement/s152_billing_resume_checked_wrapper.sh
CANONICAL_HELPER=$CANONICAL_ROOT/.github/write-enforcement/s152_billing_resume.py
DEPLOYED_WRAPPER=/home/azureuser/.local/libexec/rea_enforcement/s152_billing_resume_checked_wrapper.sh
DEPLOYED_HELPER=/home/azureuser/.local/libexec/rea_enforcement/s152_billing_resume.py

refuse() {
    printf 'REFUSE(S152_BILLING_RESUME_WRAPPER): %s\n' "$1" >&2
    printf 'SAFE_TO_PASTE_BACK=true owner_credential_handling=false\n' >&2
    exit 2
}

[ "$0" = "$DEPLOYED_WRAPPER" ] || refuse WRAPPER_PATH_MISMATCH
[ "$(hostname -s)" = gios-dev ] || refuse HOST_MISMATCH
[ "$(id -u)" -ne 0 ] || refuse ROOT_EXECUTION_REFUSED
[ "$#" -eq 0 ] || refuse ARGUMENT_REFUSED
for path in "$CANONICAL_WRAPPER" "$CANONICAL_HELPER" "$DEPLOYED_WRAPPER" "$DEPLOYED_HELPER"; do
    [ -f "$path" ] && [ ! -L "$path" ] || refuse NONREGULAR_PACKAGE_MEMBER
done
cmp -s "$DEPLOYED_WRAPPER" "$CANONICAL_WRAPPER" || refuse WRAPPER_DIGEST_MISMATCH
cmp -s "$DEPLOYED_HELPER" "$CANONICAL_HELPER" || refuse HELPER_DIGEST_MISMATCH
git -C "$CANONICAL_ROOT" diff --quiet HEAD -- \
    .github/write-enforcement/s152_billing_resume_checked_wrapper.sh \
    .github/write-enforcement/s152_billing_resume.py || refuse CANONICAL_SOURCE_DIRTY
git -C "$CANONICAL_ROOT" merge-base --is-ancestor HEAD origin/main \
    || refuse CANONICAL_COMMIT_NOT_PUBLISHED
export REA_S152_CHECKED_WRAPPER=rea-s152-billing-resume-checked-v1
exec /usr/bin/python3 "$DEPLOYED_HELPER"
