"""Path confinement and glob matching.

Every path the model supplies goes through `confine` before anything touches
the filesystem. The rule is simple: the resolved path must sit inside the
workspace, and the spelling must not be one of the known ways to alias a
different file on Windows or POSIX.
"""

from __future__ import annotations

import os
import re
import sys
from functools import lru_cache
from pathlib import Path, PurePosixPath

CASE_INSENSITIVE_FS = os.name == "nt" or sys.platform == "darwin"

_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class PathEscape(ValueError):
    """The path is not a plain location inside the workspace."""


def confine(workspace: Path, user_path: str) -> Path:
    """Return the absolute path for `user_path` inside `workspace`.

    Raises PathEscape for anything that is absolute, climbs out with `..`,
    crosses a symlink that leaves the workspace, or uses a spelling that
    Windows would silently map to another file.
    """
    if not isinstance(user_path, str) or not user_path.strip():
        raise PathEscape("empty path")
    if "\x00" in user_path:
        raise PathEscape("NUL byte in path")

    unified = user_path.replace("\\", "/")
    if unified.startswith("/"):
        raise PathEscape("absolute path")
    if ":" in unified:
        # Covers drive letters (C:/), alternate data streams (f.txt:s) and URLs.
        raise PathEscape("':' is not allowed in paths")

    for part in unified.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            continue  # judged after resolution, below
        if part != part.rstrip(". "):
            raise PathEscape(f"component {part!r} ends in a dot or space")
        if part.split(".")[0].casefold() in _WINDOWS_RESERVED:
            raise PathEscape(f"reserved device name {part!r}")

    root = workspace.resolve()
    candidate = (root / unified).resolve()
    if candidate != root and root not in candidate.parents:
        raise PathEscape("path leaves the workspace")
    return candidate


def relative_posix(workspace: Path, absolute: Path) -> str:
    """Workspace-relative path with forward slashes; '.' for the root."""
    rel = absolute.resolve().relative_to(workspace.resolve())
    text = PurePosixPath(*rel.parts).as_posix() if rel.parts else "."
    return text


@lru_cache(maxsize=512)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append(r"(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(r".*")
            i += 2
        elif ch == "*":
            out.append(r"[^/]*")
            i += 1
        elif ch == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("".join(out), re.IGNORECASE if ignore_case else 0)


def glob_match(pattern: str, rel_path: str, *, ignore_case: bool = CASE_INSENSITIVE_FS) -> bool:
    """Match a workspace-relative posix path against a glob.

    `*` and `?` stay within one path component, `**` crosses components and
    `**/` also matches zero directories, so `**/.env` matches `.env`.
    """
    return _compile(pattern, ignore_case).fullmatch(rel_path) is not None


def matches_any(patterns: list[str], rel_path: str, *, ignore_case: bool = CASE_INSENSITIVE_FS) -> str | None:
    """Return the first pattern that matches, or None."""
    for pattern in patterns:
        if glob_match(pattern, rel_path, ignore_case=ignore_case):
            return pattern
    return None
