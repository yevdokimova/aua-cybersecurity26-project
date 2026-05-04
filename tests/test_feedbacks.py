from sqlshield.feedback import FeedbackEntry, FeedbackStore


def test_add_and_lookup(tmp_path):
    store = FeedbackStore(path=str(tmp_path / "fb.json"))
    assert store.add(FeedbackEntry(
        audit_id="abc", label="false_positive",
        verdict="BLOCKED", fingerprint="ff", raw_sql="SELECT 1",
        normalized_sql="SELECT ?", reviewer="alice", note="legit query",
    ))
    assert store.get("abc").label == "false_positive"
    assert store.labels_by_id() == {"abc": "false_positive"}


def test_invalid_label_rejected(tmp_path):
    store = FeedbackStore(path=str(tmp_path / "fb.json"))
    assert not store.add(FeedbackEntry(
        audit_id="x", label="meh",
        verdict="BLOCKED", fingerprint="", raw_sql="", normalized_sql="",
    ))


def test_persisted_across_instances(tmp_path):
    p = str(tmp_path / "fb.json")
    s1 = FeedbackStore(path=p)
    s1.add(FeedbackEntry(
        audit_id="id-1", label="true_positive",
        verdict="BLOCKED", fingerprint="f", raw_sql="x", normalized_sql="x",
    ))
    s2 = FeedbackStore(path=p)
    assert s2.get("id-1").label == "true_positive"


def test_remove(tmp_path):
    store = FeedbackStore(path=str(tmp_path / "fb.json"))
    store.add(FeedbackEntry(
        audit_id="r", label="true_positive",
        verdict="ALLOWED", fingerprint="f", raw_sql="", normalized_sql="",
    ))
    assert store.remove("r")
    assert not store.remove("r")
    assert store.get("r") is None
