"""The model interface the agent loop talks to.

The transcript is a provider-neutral list:

    {"role": "user", "content": "<task>"}
    {"role": "assistant", "text": "...", "calls": [ToolCall, ...]}
    {"role": "tool", "results": [ToolResult, ...]}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..types import ToolCall

Transcript = list[dict[str, Any]]


@dataclass
class Turn:
    text: str = ""
    calls: list[ToolCall] = field(default_factory=list)

    @property
    def done(self) -> bool:
        return not self.calls


class LLM(Protocol):
    name: str

    def next_turn(self, transcript: Transcript) -> Turn: ...
