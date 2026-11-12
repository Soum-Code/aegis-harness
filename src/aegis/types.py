"""Shared data types.

Everything that crosses a trust boundary (model -> gateway -> monitor) is one
of these plain, JSON-serialisable records.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Capability(str, Enum):
    """What a tool call is asking permission to do."""

    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    FS_DELETE = "fs.delete"
    FS_LIST = "fs.list"
    PROC_EXEC = "proc.exec"
    NET_HTTP = "net.http"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"  # this call is refused, the session continues
    HALT = "halt"  # the session is over


@dataclass(frozen=True)
class ToolCall:
    """A request from the model. Untrusted."""

    tool: str
    args: dict[str, Any]
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolCall":
        return cls(tool=data["tool"], args=dict(data["args"]), call_id=data["call_id"])


@dataclass(frozen=True)
class Decision:
    """A verdict plus who made it and why."""

    verdict: Verdict
    reason: str
    source: str  # "policy", "monitor", or "gateway"
    rule: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "source": self.source,
            "rule": self.rule,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Decision":
        return cls(
            verdict=Verdict(data["verdict"]),
            reason=data["reason"],
            source=data["source"],
            rule=data.get("rule", ""),
        )


@dataclass(frozen=True)
class ToolResult:
    """What the model gets back for a call."""

    call_id: str
    ok: bool
    output: str
    decision: Decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "ok": self.ok,
            "output": self.output,
            "decision": self.decision.to_dict(),
        }
