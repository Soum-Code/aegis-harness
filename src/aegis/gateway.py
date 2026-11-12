"""The only door between the model and the machine.

For every tool call:

  1. the gateway works out what the call would touch and asks the policy;
  2. the monitor reviews the call (and logs it) whatever the policy said;
  3. the call runs only if both agreed;
  4. the output goes to the monitor before it goes back to the model.

If the monitor cannot be reached at step 2 or 4 the session halts. There is
no code path that executes a tool without a monitor verdict.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .monitor_client import MonitorClient, MonitorUnavailable
from .paths import PathEscape, confine, relative_posix
from .policy import Policy
from .sandbox import Sandbox, clip
from .tools import TOOLS
from .types import Capability, Decision, ToolCall, ToolResult, Verdict


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect could point at a host the policy never approved


class Gateway:
    def __init__(
        self,
        *,
        workspace: Path,
        policy: Policy,
        monitor: MonitorClient,
        sandbox: Sandbox,
        protected: list[Path],
    ) -> None:
        self.workspace = workspace.resolve()
        self.policy = policy
        self.monitor = monitor
        self.sandbox = sandbox
        self.protected = [p.resolve() for p in protected]
        self.halted = False
        self.halt_reason = ""

    # ---- public ------------------------------------------------------

    def execute(self, call: ToolCall) -> ToolResult:
        if self.halted:
            return self._refuse(call, Decision(Verdict.HALT, f"session halted: {self.halt_reason}", "gateway", "halted"))

        spec = TOOLS.get(call.tool)
        capability = spec.capability if spec else None
        policy_decision, target = self._policy_decision(call, capability)

        try:
            monitor_decision = self.monitor.review(call, capability, policy_decision)
        except MonitorUnavailable as exc:
            return self._halt(call, f"monitor unreachable: {exc}", "monitor-unreachable")

        decision = monitor_decision
        if monitor_decision.allowed and not policy_decision.allowed:
            decision = policy_decision  # the monitor may tighten, never loosen
        if decision.verdict is Verdict.HALT:
            self.halted, self.halt_reason = True, decision.reason
        if not decision.allowed:
            return self._refuse(call, decision)

        assert capability is not None
        try:
            ok, output = self._run(call, capability, target)
        except Exception as exc:  # a tool bug is a failed call, not a crashed harness
            ok, output = False, f"{type(exc).__name__}: {exc}"
        output = clip(output, self.policy.limits.max_output_bytes)

        try:
            ack = self.monitor.result(call.call_id, ok, output)
        except MonitorUnavailable as exc:
            return self._halt(call, f"monitor unreachable: {exc}", "monitor-unreachable")
        if ack.get("halt"):
            return self._halt(call, "monitor halted the session", "monitor-halt")
        return ToolResult(call.call_id, ok, output, decision)

    # ---- decisions ---------------------------------------------------

    def _policy_decision(self, call: ToolCall, capability: Capability | None) -> tuple[Decision, Any]:
        if capability is None:
            return _gateway_deny(f"unknown tool {call.tool!r}", "unknown-tool"), None

        if capability is Capability.PROC_EXEC:
            argv = call.args.get("argv")
            if not isinstance(argv, list):
                return _gateway_deny("argv must be a list", "bad-arguments"), None
            escape = self._argv_escape(argv)
            if escape is not None:
                return _gateway_deny(f"argument {escape!r} names a path outside the workspace", "path-confinement"), None
            return self.policy.check_exec(argv), argv

        if capability is Capability.NET_HTTP:
            url = call.args.get("url")
            parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
            if parsed is None or parsed.scheme not in ("http", "https") or not parsed.hostname:
                return _gateway_deny("url must be an http(s) URL with a host", "bad-arguments"), None
            return self.policy.check_host(parsed.hostname), url

        raw = call.args.get("path")
        if not isinstance(raw, str):
            return _gateway_deny("path must be a string", "bad-arguments"), None
        try:
            absolute = confine(self.workspace, raw)
        except PathEscape as exc:
            return _gateway_deny(f"path rejected: {exc}", "path-confinement"), None
        if any(absolute == p or p in absolute.parents for p in self.protected):
            return _gateway_deny("path is harness state", "protected-path"), None
        if capability is Capability.FS_WRITE and not isinstance(call.args.get("content"), str):
            return _gateway_deny("content must be a string", "bad-arguments"), None
        return self.policy.check_path(capability, relative_posix(self.workspace, absolute)), absolute

    def _argv_escape(self, argv: list[Any]) -> str | None:
        """The first argument that names a path outside the workspace, if any.

        A flag of an allowed command can write files too (`--junitxml=../x`),
        so anything path-like is confined like a tool path. Path-like means it
        has a slash or starts with `..`; that also refuses Windows `/switch`
        arguments, which is the safe side to err on.
        """
        for token in argv[1:]:
            for part in re.split(r"[=,;]", token) if isinstance(token, str) else ():
                unified = part.replace("\\", "/")
                if "/" not in unified and not unified.startswith(".."):
                    continue
                try:
                    resolved = (self.workspace / unified).resolve()
                except (OSError, ValueError):
                    return part
                if resolved != self.workspace and self.workspace not in resolved.parents:
                    return part
        return None

    # ---- execution ---------------------------------------------------

    def _run(self, call: ToolCall, capability: Capability, target: Any) -> tuple[bool, str]:
        if capability is Capability.FS_READ:
            return True, target.read_text(encoding="utf-8", errors="replace")
        if capability is Capability.FS_LIST:
            entries = sorted(target.iterdir(), key=lambda p: p.name.casefold())
            return True, "\n".join(p.name + ("/" if p.is_dir() else "") for p in entries)
        if capability is Capability.FS_WRITE:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-check after creating parents: the path must still be inside.
            confine(self.workspace, call.args["path"])
            target.write_text(call.args["content"], encoding="utf-8", newline="")
            return True, f"wrote {len(call.args['content'])} chars to {relative_posix(self.workspace, target)}"
        if capability is Capability.FS_DELETE:
            target.unlink()
            return True, f"deleted {relative_posix(self.workspace, target)}"
        if capability is Capability.PROC_EXEC:
            result = self.sandbox.run(
                target,
                cwd=self.workspace,
                timeout_s=self.policy.limits.exec_timeout_s,
                max_output_bytes=self.policy.limits.max_output_bytes,
            )
            return result.ok, f"[exit {result.exit_code}]\n{result.output}"
        if capability is Capability.NET_HTTP:
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(target, timeout=15) as response:
                    body = response.read(self.policy.limits.max_output_bytes + 1)
            except urllib.error.URLError as exc:
                return False, f"request failed: {exc}"
            return True, body.decode("utf-8", errors="replace")
        raise AssertionError(f"unhandled capability {capability}")

    # ---- helpers -----------------------------------------------------

    def _refuse(self, call: ToolCall, decision: Decision) -> ToolResult:
        label = "HALTED" if decision.verdict is Verdict.HALT else "DENIED"
        return ToolResult(call.call_id, False, f"{label} by {decision.source}: {decision.reason}", decision)

    def _halt(self, call: ToolCall, reason: str, rule: str) -> ToolResult:
        self.halted, self.halt_reason = True, reason
        return self._refuse(call, Decision(Verdict.HALT, reason, "gateway", rule))


def _gateway_deny(reason: str, rule: str) -> Decision:
    return Decision(Verdict.DENY, reason, "gateway", rule)
