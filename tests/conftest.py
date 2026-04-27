import os
import sys
import pytest

# Make the repo root importable (sqlshield/ lives at the top level).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """
    Each test gets its own audit log, baselines file, and allowlist file
    so persistent state from one test cannot leak into another.
    """
    audit_path     = tmp_path / "audit.jsonl"
    baselines_path = tmp_path / "baselines.json"
    allowlist_path = tmp_path / "allowlist.json"

    monkeypatch.setenv("AUDIT_LOG",      str(audit_path))
    monkeypatch.setenv("BASELINES_FILE", str(baselines_path))
    monkeypatch.setenv("ALLOWLIST",      str(allowlist_path))

    # The audit module captures LOG_FILE at import time.
    from sqlshield import audit as _audit
    monkeypatch.setattr(_audit, "LOG_FILE", str(audit_path))

    yield tmp_path
