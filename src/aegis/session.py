"""One supervised run: start the monitor, hand out a gateway, seal the log."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import VerifyReport, verify_log
from .gateway import Gateway
from .monitor import AUDIT_FILE, KEY_FILE
from .monitor_client import MonitorClient, MonitorUnavailable
from .policy import Policy
from .sandbox import LocalSandbox, Sandbox


def new_state_dir(root: Path | None = None) -> Path:
    """A fresh directory for one session's log and key, outside any workspace."""
    root = root or Path.home() / ".aegis" / "runs"
    path = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    path.mkdir(parents=True)
    return path


def make_canary() -> str:
    return f"AEGIS-CANARY-{secrets.token_hex(12)}"


@dataclass
class SessionReport:
    state_dir: Path
    outcome: str
    sealed: bool
    head: str = ""
    records: int = 0
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def log_path(self) -> Path:
        return self.state_dir / AUDIT_FILE

    def verify(self) -> VerifyReport:
        key_path = self.state_dir / KEY_FILE
        if not key_path.exists():
            # A log rewritten from scratch has a valid chain; only the MACs catch it.
            return VerifyReport(False, 0, False, "", "key file is missing: the record MACs cannot be checked")
        return verify_log(self.log_path, key_path.read_bytes())


class Session:
    """Context manager around one monitored run.

        with Session(workspace, policy, policy_path=p) as session:
            session.gateway.execute(call)
        session.report.verify()
    """

    def __init__(
        self,
        workspace: Path,
        policy: Policy,
        *,
        state_dir: Path | None = None,
        policy_path: Path | None = None,
        canaries: list[str] | None = None,
        sandbox: Sandbox | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        self.policy = policy
        self.state_dir = (state_dir or new_state_dir()).resolve()
        if self.state_dir == self.workspace or self.workspace in self.state_dir.parents:
            raise ValueError("state_dir must be outside the workspace")
        self.protected = [self.state_dir] + ([Path(policy_path).resolve()] if policy_path else [])
        self.canaries = list(canaries or [])
        self.sandbox = sandbox or LocalSandbox()
        self.meta = {"sandbox": self.sandbox.name, **(meta or {})}
        self.monitor = MonitorClient(self.state_dir)
        self.gateway: Gateway
        self.report: SessionReport

    def __enter__(self) -> "Session":
        self.monitor.start()
        try:
            self.monitor.hello(
                workspace=self.workspace,
                protected=self.protected,
                canaries=self.canaries,
                max_tool_calls=self.policy.limits.max_tool_calls,
                policy_digest=self.policy.digest,
                meta=self.meta,
            )
        except MonitorUnavailable:
            self.monitor.terminate()
            raise
        self.gateway = Gateway(
            workspace=self.workspace,
            policy=self.policy,
            monitor=self.monitor,
            sandbox=self.sandbox,
            protected=self.protected,
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is not None:
            outcome = f"error:{exc_type.__name__}"
        elif self.gateway.halted:
            outcome = "halted"
        else:
            outcome = "completed"
        try:
            reply = self.monitor.close(outcome)
            self.report = SessionReport(
                self.state_dir, outcome, True, reply["head"], reply["records"], reply["summary"]
            )
        except MonitorUnavailable:
            # The monitor is gone, so nothing sealed the log. Say so.
            self.report = SessionReport(self.state_dir, outcome, False)
