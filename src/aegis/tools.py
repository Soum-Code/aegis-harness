"""The tools the model can ask for, and the capability each one needs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .types import Capability


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capability: Capability
    description: str
    input_schema: dict[str, Any]


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


_PATH = {"type": "string", "description": "Path relative to the workspace root."}

TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "read_file",
            Capability.FS_READ,
            "Read a text file from the workspace.",
            _schema({"path": _PATH}, ["path"]),
        ),
        ToolSpec(
            "write_file",
            Capability.FS_WRITE,
            "Create or overwrite a text file in the workspace.",
            _schema({"path": _PATH, "content": {"type": "string"}}, ["path", "content"]),
        ),
        ToolSpec(
            "delete_file",
            Capability.FS_DELETE,
            "Delete a file from the workspace.",
            _schema({"path": _PATH}, ["path"]),
        ),
        ToolSpec(
            "list_dir",
            Capability.FS_LIST,
            "List a directory in the workspace. Directories end with '/'.",
            _schema({"path": _PATH}, ["path"]),
        ),
        ToolSpec(
            "run",
            Capability.PROC_EXEC,
            "Run a program without a shell. argv[0] is a program name, not a path.",
            _schema({"argv": {"type": "array", "items": {"type": "string"}, "minItems": 1}}, ["argv"]),
        ),
        ToolSpec(
            "http_get",
            Capability.NET_HTTP,
            "Fetch a URL over HTTP(S).",
            _schema({"url": {"type": "string"}}, ["url"]),
        ),
    )
}
