"""The agent loop: model proposes, gateway disposes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .gateway import Gateway
from .llm.base import LLM, Transcript
from .types import ToolResult


@dataclass
class AgentOutcome:
    stop_reason: str  # "finished", "halted", or "max_turns"
    final_text: str
    turns: int
    results: list[ToolResult] = field(default_factory=list)
    transcript: Transcript = field(default_factory=list)

    @property
    def executed(self) -> list[ToolResult]:
        return [r for r in self.results if r.decision.allowed]

    @property
    def refused(self) -> list[ToolResult]:
        return [r for r in self.results if not r.decision.allowed]


def run_agent(llm: LLM, gateway: Gateway, task: str, *, max_turns: int = 40) -> AgentOutcome:
    transcript: Transcript = [{"role": "user", "content": task}]
    results: list[ToolResult] = []
    final_text = ""

    for turn_no in range(1, max_turns + 1):
        turn = llm.next_turn(transcript)
        final_text = turn.text
        transcript.append({"role": "assistant", "text": turn.text, "calls": turn.calls})
        if turn.done:
            return AgentOutcome("finished", final_text, turn_no, results, transcript)

        turn_results = [gateway.execute(call) for call in turn.calls]
        results.extend(turn_results)
        transcript.append({"role": "tool", "results": turn_results})
        if gateway.halted:
            return AgentOutcome("halted", final_text, turn_no, results, transcript)

    return AgentOutcome("max_turns", final_text, max_turns, results, transcript)
