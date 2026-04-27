from sqlshield.allowlist import AllowlistEntry, AllowlistStore


def test_add_remove(tmp_path):
    store = AllowlistStore(path=str(tmp_path / "a.json"))
    e = AllowlistEntry(fingerprint="abc", reason="false positive")
    assert store.add(e) is True
    assert store.contains("abc") is True
    # Duplicate add is rejected.
    assert store.add(AllowlistEntry(fingerprint="abc")) is False

    assert store.remove("abc") is True
    assert store.contains("abc") is False
    assert store.remove("abc") is False


def test_persistence(tmp_path):
    path = str(tmp_path / "a.json")
    s1 = AllowlistStore(path=path)
    s1.add(AllowlistEntry(fingerprint="fp-1", reason="why"))
    s1.add(AllowlistEntry(fingerprint="fp-2"))

    s2 = AllowlistStore(path=path)
    fps = {e.fingerprint for e in s2.list_all()}
    assert fps == {"fp-1", "fp-2"}


def test_empty_fingerprint_rejected(tmp_path):
    store = AllowlistStore(path=str(tmp_path / "a.json"))
    assert store.add(AllowlistEntry(fingerprint="")) is False
