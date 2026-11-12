import json

import pytest

from aegis.audit import GENESIS, AuditLog, read_records, verify_log

KEY = b"k" * 32


@pytest.fixture
def sealed_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, KEY)
    log.append("session", {"workspace": "/w"})
    for i in range(4):
        log.append("review", {"call_id": f"c{i}", "verdict": "allow"})
    seal = log.seal({"outcome": "completed"})
    return path, seal["hash"]


def _lines(path):
    return path.read_text(encoding="ascii").splitlines()


def _write(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


def test_clean_log_verifies(sealed_log):
    path, head = sealed_log
    report = verify_log(path, KEY)
    assert report.ok and report.sealed and report.records == 6 and report.head == head
    assert verify_log(path).ok  # chain only, no key


def test_records_chain_from_genesis(sealed_log):
    records = read_records(sealed_log[0])
    assert records[0]["prev"] == GENESIS
    assert [r["seq"] for r in records] == list(range(6))
    assert all(later["prev"] == earlier["hash"] for earlier, later in zip(records, records[1:]))


def test_edited_record_is_detected(sealed_log):
    path, _ = sealed_log
    lines = _lines(path)
    record = json.loads(lines[2])
    record["payload"]["verdict"] = "deny"
    lines[2] = json.dumps(record)
    _write(path, lines)
    report = verify_log(path, KEY)
    assert not report.ok and "record 2" in report.error and report.records == 2


def test_dropped_record_is_detected(sealed_log):
    path, _ = sealed_log
    lines = _lines(path)
    del lines[3]
    _write(path, lines)
    assert not verify_log(path, KEY).ok


def test_swapped_records_are_detected(sealed_log):
    path, _ = sealed_log
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write(path, lines)
    assert not verify_log(path, KEY).ok


def test_truncation_is_detected_by_the_missing_seal(sealed_log):
    path, _ = sealed_log
    _write(path, _lines(path)[:-2])
    report = verify_log(path, KEY)
    assert not report.ok and "seal" in report.error
    relaxed = verify_log(path, KEY, require_seal=False)
    assert relaxed.ok and not relaxed.sealed and relaxed.records == 4


def test_record_after_the_seal_is_detected(sealed_log):
    path, head = sealed_log
    lines = _lines(path)
    extra = json.loads(lines[1])
    extra.update(seq=6, prev=head)
    lines.append(json.dumps(extra))
    _write(path, lines)
    report = verify_log(path, KEY)
    assert not report.ok and "after the seal" in report.error


def _rebuild_chain(path, forge_key):
    """What an attacker without the real key can do: rewrite everything."""
    forged = path.with_name("forged.jsonl")
    log = AuditLog(forged, forge_key)
    records = read_records(path)
    for record in records[:-1]:
        payload = dict(record["payload"])
        if payload.get("call_id") == "c2":
            continue  # the record the attacker wants gone
        log.append(record["kind"], payload)
    log.seal(records[-1]["payload"])
    path.write_bytes(forged.read_bytes())


def test_full_rewrite_without_the_key_fails_the_mac(sealed_log):
    path, head = sealed_log
    _rebuild_chain(path, b"not-the-key")
    assert verify_log(path).ok, "the chain alone cannot catch a full rewrite"
    assert not verify_log(path, KEY).ok
    assert "MAC" in verify_log(path, KEY).error


def test_full_rewrite_with_a_stolen_key_changes_the_head(sealed_log):
    # Documented limit: with the key, a rewritten log verifies. The head hash
    # the harness reported at the end of the session is what still gives it away.
    path, head = sealed_log
    _rebuild_chain(path, KEY)
    report = verify_log(path, KEY)
    assert report.ok
    assert report.head != head


def test_sealed_log_refuses_more_records(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", KEY)
    log.seal({})
    with pytest.raises(RuntimeError):
        log.append("review", {})


def test_a_log_file_is_never_reused(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path, KEY).seal({})
    with pytest.raises(FileExistsError):
        AuditLog(path, KEY)


def test_garbage_and_missing_files(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert not verify_log(path, KEY).ok
    path.write_text("not json\n", encoding="ascii")
    assert "well-formed" in verify_log(path, KEY).error
