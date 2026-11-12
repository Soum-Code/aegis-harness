"""The monitor: a separate process that reviews every tool call and owns the log.

Run as `python -m aegis.monitor --state-dir DIR`. The parent writes a one-line
JSON handshake to stdin (the IPC auth key); the monitor answers on stdout with
the port it is listening on. Neither the auth key nor the audit key is ever
placed in argv or the environment, where a sandboxed child could read them.

Messages are JSON over `multiprocessing.connection` byte frames. Pickle is
never used, so a compromised peer cannot make this process run code.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from multiprocessing.connection import Connection, Listener
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .detectors import SessionState, canary_forms, observe_output, review
from .types import Capability, Decision, ToolCall, Verdict

AUDIT_FILE = "audit.jsonl"
KEY_FILE = "audit.key"
OUTPUT_EXCERPT_CHARS = 400
REDACTED = "[planted-secret]"


def _send(conn: Connection, message: dict[str, Any]) -> None:
    conn.send_bytes(json.dumps(message).encode("utf-8"))


def _recv(conn: Connection) -> dict[str, Any]:
    return json.loads(conn.recv_bytes(maxlength=8 * 1024 * 1024).decode("utf-8"))


class MonitorServer:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        key = secrets.token_bytes(32)
        key_path = state_dir / KEY_FILE
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        self.log = AuditLog(state_dir / AUDIT_FILE, key)
        self.state: SessionState | None = None
        self.halted = False
        self.pending: dict[str, ToolCall] = {}

    def handle(self, message: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Return (reply, keep_running)."""
        op = message.get("op")
        if op == "hello":
            return self._hello(message), True
        if op == "close":
            return self._close(message), False
        if self.state is None:
            return {"error": "session not started"}, True
        if op == "review":
            return self._review(message), True
        if op == "result":
            return self._result(message), True
        return {"error": f"unknown op {op!r}"}, True

    def _hello(self, message: dict[str, Any]) -> dict[str, Any]:
        if self.state is not None:
            return {"error": "session already started"}
        workspace = Path(message["workspace"]).resolve()
        protected = [Path(p).resolve() for p in message.get("protected", [])]
        protected.append(self.state_dir.resolve())
        self.state = SessionState(
            workspace=workspace,
            protected=protected,
            canaries=list(message.get("canaries", [])),
            monitor_pids=[os.getpid(), *message.get("extra_pids", [])],
            max_tool_calls=int(message["max_tool_calls"]),
        )
        self.log.append(
            "session_start",
            {
                "workspace": str(workspace),
                "policy_digest": message.get("policy_digest", ""),
                "protected": [str(p) for p in protected],
                "canary_count": len(self.state.canaries),
                "monitor_pid": os.getpid(),
                "meta": message.get("meta", {}),
            },
        )
        return {"ok": True, "pid": os.getpid()}

    def _review(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self.state is not None
        call = ToolCall.from_dict(message["call"])
        capability = Capability(message["capability"]) if message.get("capability") else None
        policy = Decision.from_dict(message["policy"])
        if self.halted:
            decision = Decision(Verdict.HALT, "session already halted", "monitor", "halted")
        else:
            decision = review(self.state, call, capability, policy)
        if decision.verdict is Verdict.HALT:
            self.halted = True
        if decision.allowed:
            self.pending[call.call_id] = call
        self.log.append(
            "tool_call",
            {
                "call": self._redact(call.to_dict()),
                "capability": capability.value if capability else None,
                "policy": policy.to_dict(),
                "decision": decision.to_dict(),
            },
        )
        return {"decision": decision.to_dict()}

    def _result(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self.state is not None
        call = self.pending.pop(message["call_id"], None)
        if call is None:
            # A result for a call we never approved means the gateway ran
            # something without asking. Record it loudly and stop the session.
            self.halted = True
            self.log.append("violation", {"rule": "unreviewed-execution", "call_id": message["call_id"]})
            return {"ok": False, "halt": True}
        output = str(message.get("output", ""))
        hits = observe_output(self.state, call, output)
        self.log.append(
            "tool_result",
            {
                "call_id": call.call_id,
                "ok": bool(message.get("ok")),
                "output_chars": len(output),
                "output_excerpt": self._redact(output[:OUTPUT_EXCERPT_CHARS + 64])[:OUTPUT_EXCERPT_CHARS],
                "injection_patterns": hits,
            },
        )
        return {"ok": True, "tainted": bool(self.state.tainted_by)}

    def _redact(self, value: Any) -> Any:
        """Keep planted secrets out of the log: it is evidence, not a second copy."""
        canaries = self.state.canaries if self.state else []
        if isinstance(value, str):
            for canary in canaries:
                for needles in canary_forms(canary).values():  # the encodings the canary rule knows
                    for needle in needles:
                        value = value.replace(needle, REDACTED)
            return value
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value

    def _close(self, message: dict[str, Any]) -> dict[str, Any]:
        state = self.state
        summary = {
            "outcome": message.get("outcome", "closed"),
            "calls": state.calls if state else 0,
            "halted": self.halted,
            "tainted_by": state.tainted_by if state else "",
            "findings": state.findings if state else [],
        }
        record = self.log.seal(summary)
        return {"ok": True, "head": record["hash"], "records": self.log.length, "summary": summary}


def serve(state_dir: Path) -> int:
    handshake = json.loads(sys.stdin.readline())
    authkey = bytes.fromhex(handshake["authkey"])
    server = MonitorServer(state_dir)
    with Listener(("127.0.0.1", 0), authkey=authkey) as listener:
        print(json.dumps({"port": listener.address[1], "pid": os.getpid()}), flush=True)
        with listener.accept() as conn:
            running = True
            while running:
                try:
                    message = _recv(conn)
                except (EOFError, OSError):
                    # The harness went away without closing. Seal what we have
                    # so the log says so instead of looking truncated.
                    server.handle({"op": "close", "outcome": "harness-disconnected"})
                    return 1
                try:
                    reply, running = server.handle(message)
                except Exception as exc:  # a malformed message must not kill the monitor
                    reply, running = {"error": f"{type(exc).__name__}: {exc}"}, True
                _send(conn, reply)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="aegis.monitor")
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    return serve(args.state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
