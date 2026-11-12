"""A monitor that agrees with everything. For measurement only.

The red-team suite uses it for the `no-monitor` baseline: the same attacks
against a harness with a wide-open policy and no detectors. It keeps no log
and stops nothing, so it must never be used for a real session.
"""

from __future__ import annotations

from typing import Any

from ..types import Capability, Decision, ToolCall, Verdict


class NullMonitor:
    pid = 0
    proc = None

    def review(self, call: ToolCall, capability: Capability | None, policy: Decision) -> Decision:
        if not policy.allowed:
            return policy
        return Decision(Verdict.ALLOW, "baseline: nothing is reviewed", "baseline", "none")

    def result(self, call_id: str, ok: bool, output: str) -> dict[str, Any]:
        return {}
