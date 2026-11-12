"""Capability policy: default deny, loaded from a TOML file.

The policy answers one question per tool call: is this (capability, target)
pair on the allow list and off the deny list? Deny always wins, and deny
patterns are matched case-insensitively on every platform so a rule written
for `.env` also catches `.ENV`.
"""

from __future__ import annotations

import fnmatch
import hashlib
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

from .paths import matches_any
from .types import Capability, Decision, Verdict

PATH_CAPABILITIES = (
    Capability.FS_READ,
    Capability.FS_WRITE,
    Capability.FS_DELETE,
    Capability.FS_LIST,
)

ARGV_TAIL = "..."


class PolicyError(ValueError):
    """The policy file is malformed."""


@dataclass(frozen=True)
class Limits:
    max_tool_calls: int = 60
    max_output_bytes: int = 65_536
    exec_timeout_s: float = 60.0


@dataclass(frozen=True)
class PathRule:
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    limits: Limits = field(default_factory=Limits)
    paths: dict[Capability, PathRule] = field(default_factory=dict)
    exec_allow: tuple[tuple[str, ...], ...] = ()
    net_allow: tuple[str, ...] = ()
    digest: str = ""  # sha256 of the source file, recorded in the audit log

    # ---- loading -----------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Policy":
        raw = Path(path).read_bytes()
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise PolicyError(f"cannot parse {path}: {exc}") from exc
        return cls.from_dict(data, digest=hashlib.sha256(raw).hexdigest())

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, digest: str = "") -> "Policy":
        if data.get("version") != 1:
            raise PolicyError("policy must declare version = 1")

        try:
            limits = Limits(**_table(data, "limits"))
        except TypeError as exc:
            raise PolicyError(f"[limits] has an unknown key: {exc}") from exc
        fs = _table(data, "fs")
        paths: dict[Capability, PathRule] = {}
        for cap in PATH_CAPABILITIES:
            section = _table(fs, cap.value.split(".")[1])
            paths[cap] = PathRule(
                allow=_strings(section.get("allow", []), f"{cap.value}.allow"),
                deny=_strings(section.get("deny", []), f"{cap.value}.deny"),
            )

        exec_rules = _table(_table(data, "proc"), "exec").get("allow", [])
        if not isinstance(exec_rules, list):
            raise PolicyError("proc.exec.allow must be a list of argv patterns")
        exec_allow = tuple(_strings(rule, "proc.exec.allow[]") for rule in exec_rules)
        if any(not rule for rule in exec_allow):
            raise PolicyError("proc.exec.allow contains an empty argv pattern")

        net_allow = _strings(_table(_table(data, "net"), "http").get("allow", []), "net.http.allow")
        return cls(limits=limits, paths=paths, exec_allow=exec_allow, net_allow=net_allow, digest=digest)

    # ---- checks ------------------------------------------------------

    def check_path(self, capability: Capability, rel_path: str) -> Decision:
        rule = self.paths.get(capability, PathRule())
        denied = matches_any(list(rule.deny), rel_path, ignore_case=True)
        if denied:
            return _deny(f"{capability.value} on {rel_path!r} matches deny rule {denied!r}", denied)
        allowed = matches_any(list(rule.allow), rel_path)
        if allowed:
            return _allow(f"{capability.value} on {rel_path!r} allowed by {allowed!r}", allowed)
        return _deny(f"{capability.value} on {rel_path!r} is not on the allow list", "default-deny")

    def check_exec(self, argv: list[str]) -> Decision:
        if not argv or not all(isinstance(a, str) and a for a in argv):
            return _deny("argv must be a non-empty list of non-empty strings", "argv-shape")
        normalised = [_program_name(argv[0]), *argv[1:]]
        for pattern in self.exec_allow:
            if _argv_matches(pattern, normalised):
                return _allow(f"exec {normalised[0]!r} allowed by {list(pattern)!r}", " ".join(pattern))
        return _deny(f"exec {' '.join(argv)!r} is not on the allow list", "default-deny")

    def check_host(self, host: str) -> Decision:
        host = host.casefold().rstrip(".")
        for pattern in self.net_allow:
            if fnmatch.fnmatchcase(host, pattern.casefold()):
                return _allow(f"host {host!r} allowed by {pattern!r}", pattern)
        return _deny(f"network access to {host!r} is not on the allow list", "default-deny")


def _program_name(argv0: str) -> str:
    """`C:\\Python\\python.EXE` and `python` are the same program to a rule.

    A rule names a program, not a location, so an argv[0] that carries a
    directory is refused outright rather than matched by basename.
    """
    name = PurePath(argv0.replace("\\", "/")).name
    if name != argv0:
        return f"<path:{argv0}>"
    lowered = name.casefold()
    return lowered[:-4] if lowered.endswith(".exe") else lowered


def _argv_matches(pattern: tuple[str, ...], argv: list[str]) -> bool:
    open_tail = pattern[-1] == ARGV_TAIL
    fixed = pattern[:-1] if open_tail else pattern
    if len(argv) < len(fixed) or (not open_tail and len(argv) != len(fixed)):
        return False
    return all(fnmatch.fnmatchcase(arg, pat) for arg, pat in zip(argv, fixed))


def _allow(reason: str, rule: str) -> Decision:
    return Decision(Verdict.ALLOW, reason, "policy", rule)


def _deny(reason: str, rule: str) -> Decision:
    return Decision(Verdict.DENY, reason, "policy", rule)


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise PolicyError(f"[{key}] must be a table")
    return value


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings")
    return tuple(value)
