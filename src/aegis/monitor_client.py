"""Harness-side handle on the monitor process.

Any failure to get an answer raises `MonitorUnavailable`. The gateway treats
that as a halt: no monitor, no tool calls.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
from multiprocessing.connection import Client, Connection
from pathlib import Path
from typing import Any

from .types import Capability, Decision, ToolCall

PACKAGE_PARENT = Path(__file__).resolve().parents[1]


class MonitorUnavailable(RuntimeError):
    """The monitor did not answer. Fail closed."""


class MonitorClient:
    def __init__(self, state_dir: Path, *, timeout: float = 10.0) -> None:
        self.state_dir = Path(state_dir)
        self.timeout = timeout
        self.proc: subprocess.Popen[bytes] | None = None
        self.conn: Connection | None = None
        self.pid: int = 0

    # ---- lifecycle ---------------------------------------------------

    def start(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        authkey = secrets.token_bytes(32)
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(PACKAGE_PARENT), env.get("PYTHONPATH", "")]))
        stderr = open(self.state_dir / "monitor.stderr.log", "wb")
        try:
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "aegis.monitor", "--state-dir", str(self.state_dir)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                env=env,
                cwd=self.state_dir,
            )
        finally:
            stderr.close()
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"authkey": authkey.hex()}).encode() + b"\n")
        self.proc.stdin.close()

        line = self._read_line_with_timeout()
        try:
            info = json.loads(line)
            self.pid = int(info["pid"])
            self.conn = Client(("127.0.0.1", int(info["port"])), authkey=authkey)
        except Exception as exc:
            self.terminate()
            raise MonitorUnavailable(f"monitor did not start: {exc}") from exc

    def _read_line_with_timeout(self) -> bytes:
        assert self.proc and self.proc.stdout
        box: list[bytes] = []
        reader = threading.Thread(target=lambda: box.append(self.proc.stdout.readline()), daemon=True)
        reader.start()
        reader.join(self.timeout)
        if not box or not box[0]:
            self.terminate()
            raise MonitorUnavailable("monitor did not report a port")
        return box[0]

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def terminate(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if self.proc.stdout:
                self.proc.stdout.close()

    # ---- protocol ----------------------------------------------------

    def _request(self, message: dict[str, Any]) -> dict[str, Any]:
        if self.conn is None or not self.alive():
            raise MonitorUnavailable("monitor process is not running")
        try:
            self.conn.send_bytes(json.dumps(message).encode("utf-8"))
            if not self.conn.poll(self.timeout):
                raise MonitorUnavailable("monitor did not answer in time")
            reply = json.loads(self.conn.recv_bytes().decode("utf-8"))
        except (OSError, EOFError, ValueError) as exc:
            raise MonitorUnavailable(f"monitor connection failed: {exc}") from exc
        if "error" in reply:
            raise MonitorUnavailable(f"monitor rejected the request: {reply['error']}")
        return reply

    def hello(
        self,
        *,
        workspace: Path,
        protected: list[Path],
        canaries: list[str],
        max_tool_calls: int,
        policy_digest: str,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self._request(
            {
                "op": "hello",
                "workspace": str(workspace),
                "protected": [str(p) for p in protected],
                "canaries": canaries,
                "max_tool_calls": max_tool_calls,
                "policy_digest": policy_digest,
                "extra_pids": [os.getpid()],
                "meta": meta or {},
            }
        )

    def review(self, call: ToolCall, capability: Capability | None, policy: Decision) -> Decision:
        reply = self._request(
            {
                "op": "review",
                "call": call.to_dict(),
                "capability": capability.value if capability else None,
                "policy": policy.to_dict(),
            }
        )
        return Decision.from_dict(reply["decision"])

    def result(self, call_id: str, ok: bool, output: str) -> dict[str, Any]:
        return self._request({"op": "result", "call_id": call_id, "ok": ok, "output": output})

    def close(self, outcome: str) -> dict[str, Any]:
        try:
            reply = self._request({"op": "close", "outcome": outcome})
        finally:
            if self.proc is not None:
                try:
                    self.proc.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    pass
            self.terminate()
        return reply
