#!/usr/bin/env bash
# One no-argument row drives the complete s212 credential-recovery arc.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ $# -ne 0 ]]; then
  echo 'S212_WEA_RECOVERY_REFUSED reason=OWNER_ROW_TAKES_NO_ARGUMENTS' >&2
  exit 3
fi
if [[ "$(hostname)" != gios-dev || "$(id -un)" != azureuser ]]; then
  echo 'S212_WEA_RECOVERY_REFUSED reason=OWNER_LOCUS_REFUSED' >&2
  exit 3
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'S212_WEA_RECOVERY_REFUSED reason=OWNER_TTY_REQUIRED' >&2
  exit 3
fi
exec /usr/bin/python3 "$ROOT/s212_wea_credential_recovery.py" --apply
