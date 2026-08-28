#!/usr/bin/env bash
set -euo pipefail

REPOSITORY=/home/azureuser/rexcoleman.dev
MOONSHOTS_REPOSITORY=/home/azureuser/Moonshots_Career_Thesis_v2
CREDENTIAL_TOOL=$REPOSITORY/.github/write-enforcement/populate_rea_s170_govml_credentials.py
PRINCIPAL_TOOL=$REPOSITORY/.github/write-enforcement/setup_external_judge_hosted_principal.py
PRINCIPAL_WRAPPER=$REPOSITORY/.github/write-enforcement/setup_external_judge_hosted_principal.sh
ENROLLMENT_TOOL=$MOONSHOTS_REPOSITORY/scripts/enroll_research_repository_secrets.py

REMOTE=$(/usr/bin/git -C "$REPOSITORY" ls-remote origin refs/heads/main)
read -r COMMIT REF TRAILING <<<"$REMOTE"
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ || "$REF" != refs/heads/main || -n "${TRAILING:-}" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=PAYLOAD_COMMIT_REFUSED' >&2
  exit 3
fi
if [[ "$(/usr/bin/git -C "$REPOSITORY" rev-parse HEAD)" != "$COMMIT" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=PAYLOAD_HEAD_REFUSED' >&2
  exit 3
fi
PAYLOAD=(
  .github/write-enforcement/populate_rea_s170_govml_credentials.py
  .github/write-enforcement/rea_s170_owner_arc.sh
  .github/write-enforcement/setup_external_judge_hosted_principal.py
  .github/write-enforcement/setup_external_judge_hosted_principal.sh
  .github/workflows/issue-external-judge-authority.yml
)
if [[ -n "$(/usr/bin/git -C "$REPOSITORY" status --porcelain -- "${PAYLOAD[@]}")" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=PAYLOAD_DIRTY_REFUSED' >&2
  exit 3
fi
if ! /usr/bin/git -C "$REPOSITORY" diff --quiet "$COMMIT" -- "${PAYLOAD[@]}"; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=PAYLOAD_BYTES_REFUSED' >&2
  exit 3
fi

MOONSHOTS_REMOTE=$(/usr/bin/git -C "$MOONSHOTS_REPOSITORY" ls-remote origin refs/heads/main)
read -r MOONSHOTS_COMMIT MOONSHOTS_REF MOONSHOTS_TRAILING <<<"$MOONSHOTS_REMOTE"
if [[ ! "$MOONSHOTS_COMMIT" =~ ^[0-9a-f]{40}$ || "$MOONSHOTS_REF" != refs/heads/main || -n "${MOONSHOTS_TRAILING:-}" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=ENROLLMENT_COMMIT_REFUSED' >&2
  exit 3
fi
if [[ "$(/usr/bin/git -C "$MOONSHOTS_REPOSITORY" rev-parse HEAD)" != "$MOONSHOTS_COMMIT" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=ENROLLMENT_HEAD_REFUSED' >&2
  exit 3
fi
if [[ -n "$(/usr/bin/git -C "$MOONSHOTS_REPOSITORY" status --porcelain -- scripts/enroll_research_repository_secrets.py)" ]]; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=ENROLLMENT_DIRTY_REFUSED' >&2
  exit 3
fi
if ! /usr/bin/git -C "$MOONSHOTS_REPOSITORY" diff --quiet "$MOONSHOTS_COMMIT" -- scripts/enroll_research_repository_secrets.py; then
  printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=ENROLLMENT_BYTES_REFUSED' >&2
  exit 3
fi

case "${1:-}" in
  --preflight)
    /usr/bin/python3 "$CREDENTIAL_TOOL" --preflight
    exec /usr/bin/python3 "$PRINCIPAL_TOOL" --preflight
    ;;
  --apply)
    /usr/bin/python3 "$CREDENTIAL_TOOL" --preflight
    /usr/bin/python3 "$PRINCIPAL_TOOL" --preflight
    /usr/bin/python3 "$CREDENTIAL_TOOL" --apply
    /usr/bin/python3 "$ENROLLMENT_TOOL" /home/azureuser --repository rexcoleman/adversarial-ml-landscape
    exec /usr/bin/bash "$PRINCIPAL_WRAPPER"
    ;;
  --final-exec-self-test)
    test -t 0
    test -t 1
    test -t 2
    /usr/bin/python3 "$CREDENTIAL_TOOL" --preflight
    exec /usr/bin/python3 "$PRINCIPAL_TOOL" --preflight
    ;;
  *)
    printf '%s\n' 'REA_S170_OWNER_ARC_REFUSED reason=ARGUMENT_REFUSED' >&2
    exit 3
    ;;
esac
