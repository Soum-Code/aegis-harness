"""A deterministic stand-in for a model.

Used for tests and for the red-team suite, where the "model" is an adversary
whose moves we want to replay exactly. A move is either a fixed list of tool
calls or a function of the transcript, for attackers that react to what the
tools returned.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Union

from ..types import ToolCall
from .base import Transcript, Turn

Move = Union[list[ToolCall], Callable[[Transcript], list[ToolCall]]]


def call(tool: str, **args: Any) -> ToolCall:
    return ToolCall(tool=tool, args=args)


class ScriptedLLM:
    name = "scripted"

    def __init__(self, moves: Iterable[Move]) -> None:
        self._moves = list(moves)
        self._index = 0

    def next_turn(self, transcript: Transcript) -> Turn:
        if self._index >= len(self._moves):
            return Turn(text="done")
        move = self._moves[self._index]
        self._index += 1
        calls = move(transcript) if callable(move) else move
        return Turn(text=f"scripted move {self._index}", calls=list(calls))


def last_tool_output(transcript: Transcript) -> str:
    """Text of the most recent tool results, for reactive moves."""
    for entry in reversed(transcript):
        if entry["role"] == "tool":
            return "\n".join(result.output for result in entry["results"])
    return ""
