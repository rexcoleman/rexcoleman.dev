import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("issue_wea", ROOT / "issue_wea.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_active_and_expired_fixture_windows_are_closed_and_remote_issuer_owned():
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    assert module.issuance_times(now, "active") == (now, now + timedelta(hours=24))
    assert module.issuance_times(now, "expired_fixture") == (now - timedelta(hours=48), now - timedelta(hours=24))
    with pytest.raises(ValueError):
        module.issuance_times(now, "caller_time")
