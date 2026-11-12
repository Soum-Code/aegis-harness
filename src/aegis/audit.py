"""Append-only, hash-chained audit log.

Each record carries the hash of the one before it and an HMAC over its own
hash. Editing, reordering or dropping a record in the middle breaks the
chain. Cutting records off the end is caught by the seal: a finished session
ends with a `seal` record, so a log whose last record is anything else was
truncated or the monitor died mid-session.

Only the monitor process writes this file and only it holds the key while a
session is running.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
SEAL = "seal"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _record_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


def _mac(key: bytes, record_hash: str) -> str:
    return hmac.new(key, record_hash.encode("ascii"), hashlib.sha256).hexdigest()


class AuditLog:
    """Writer side. One instance per session, one session per file."""

    def __init__(self, path: Path, key: bytes) -> None:
        self.path = Path(path)
        self._key = key
        self._seq = 0
        self._head = GENESIS
        self._sealed = False
        # "x" refuses to reuse a file, so a session can never extend old history.
        self._fh = open(self.path, "x", encoding="ascii", newline="\n")

    @property
    def head(self) -> str:
        return self._head

    @property
    def length(self) -> int:
        return self._seq

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._sealed:
            raise RuntimeError("audit log is sealed")
        body = {
            "seq": self._seq,
            "ts": round(time.time(), 6),
            "kind": kind,
            "payload": payload,
            "prev": self._head,
        }
        digest = _record_hash(body)
        record = {**body, "hash": digest, "mac": _mac(self._key, digest)}
        self._fh.write(canonical(record).decode("ascii") + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._seq += 1
        self._head = digest
        return record

    def seal(self, summary: dict[str, Any]) -> dict[str, Any]:
        record = self.append(SEAL, summary)
        self._sealed = True
        self._fh.close()
        return record


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    records: int
    sealed: bool
    head: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "sealed": self.sealed,
            "head": self.head,
            "error": self.error,
        }


def verify_log(path: Path, key: bytes | None = None, *, require_seal: bool = True) -> VerifyReport:
    """Re-walk the chain. With `key`, also check every record's HMAC.

    Without the key this proves internal consistency only: someone who can
    rewrite the whole file can rebuild a consistent chain, but not valid MACs.
    """
    prev = GENESIS
    count = 0
    last_kind = ""

    def fail(message: str) -> VerifyReport:
        return VerifyReport(False, count, False, prev, message)

    try:
        lines = Path(path).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return fail(f"cannot read log: {exc}")

    for line_no, line in enumerate(lines):
        try:
            record = json.loads(line)
            body = {k: record[k] for k in ("seq", "ts", "kind", "payload", "prev")}
            claimed_hash = record["hash"]
            claimed_mac = record["mac"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return fail(f"record {line_no} is not a well-formed entry")
        if last_kind == SEAL:
            return fail(f"record {line_no} appears after the seal")
        if body["seq"] != count:
            return fail(f"record {line_no} has seq {body['seq']}, expected {count}")
        if body["prev"] != prev:
            return fail(f"record {line_no} does not link to the previous record")
        if _record_hash(body) != claimed_hash:
            return fail(f"record {line_no} was modified (hash mismatch)")
        if key is not None and not hmac.compare_digest(_mac(key, claimed_hash), str(claimed_mac)):
            return fail(f"record {line_no} has an invalid MAC")
        prev = claimed_hash
        last_kind = body["kind"]
        count += 1

    sealed = last_kind == SEAL
    if require_seal and not sealed:
        return VerifyReport(False, count, False, prev, "log has no seal: truncated or session did not finish")
    return VerifyReport(True, count, sealed, prev)


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="ascii").splitlines() if line]
