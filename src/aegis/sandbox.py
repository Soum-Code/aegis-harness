"""Where allowed commands actually run.

`LocalSandbox` is process hygiene, not isolation: no shell, a scrubbed
environment, a working directory, a timeout and an output cap. Code that runs
in it has the same OS user as the harness. Treat it as a development backend
and use a container backend when the code under test is not trusted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# The only variables a child inherits. API keys and tokens in the parent
# environment never reach code the agent runs.
ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "HOME", "USERPROFILE")


@dataclass(frozen=True)
class ExecResult:
    ok: bool
    exit_code: int | None
    output: str


class Sandbox(Protocol):
    name: str

    def run(self, argv: list[str], *, cwd: Path, timeout_s: float, max_output_bytes: int) -> ExecResult: ...


def clip(text: str, max_bytes: int) -> str:
    data = text.encode("utf-8", errors="replace")
    if len(data) <= max_bytes:
        return text
    kept = data[:max_bytes].decode("utf-8", errors="ignore")
    return f"{kept}\n[output truncated: {len(data) - max_bytes} more bytes]"


class LocalSandbox:
    name = "local"

    def run(self, argv: list[str], *, cwd: Path, timeout_s: float, max_output_bytes: int) -> ExecResult:
        program = self._resolve(argv[0])
        if program is None:
            return ExecResult(False, None, f"program not found: {argv[0]}")
        env = {k: v for k, v in os.environ.items() if k.upper() in ENV_ALLOWLIST}
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            done = subprocess.run(
                [program, *argv[1:]],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout_s,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial = (exc.stdout or b"").decode("utf-8", errors="replace")
            return ExecResult(False, None, clip(partial, max_output_bytes) + f"\n[timed out after {timeout_s}s]")
        except OSError as exc:
            return ExecResult(False, None, f"could not start {argv[0]}: {exc}")
        output = done.stdout.decode("utf-8", errors="replace")
        return ExecResult(done.returncode == 0, done.returncode, clip(output, max_output_bytes))

    @staticmethod
    def _resolve(program: str) -> str | None:
        # "python" means the interpreter running the harness. On Windows the
        # bare name can resolve to the Store alias stub, which is not Python.
        if program.casefold() in ("python", "python3", "python.exe"):
            return sys.executable
        return shutil.which(program)
