import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("issue_wea", ROOT / "issue_wea.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_only_active_successor_window_is_exposed():
    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    assert module.issuance_times(now) == (now, now + timedelta(hours=24))
