"""The Claude adapter against a fake client: no network, no SDK needed."""

import sys
from types import SimpleNamespace

from aegis.agent import run_agent
from aegis.cli import main as cli
from aegis.gateway import Gateway
from aegis.llm.claude import DEFAULT_MODEL, ClaudeLLM
from aegis.redteam.baseline import NullMonitor
from aegis.sandbox import LocalSandbox


def text(value):
    return SimpleNamespace(type="text", text=value)


def tool_use(call_id, name, **arguments):
    return SimpleNamespace(type="tool_use", id=call_id, name=name, input=arguments)


def reply(*blocks, stop_reason="tool_use"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop_reason)


class FakeClient:
    """Stands in for anthropic.Anthropic(): records requests, replays replies."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **request):
        self.requests.append({**request, "messages": list(request["messages"])})
        return self._replies.pop(0)


def gateway_for(project):
    return Gateway(
        workspace=project.workspace,
        policy=project.policy(),  # the default policy: .env is off limits
        monitor=NullMonitor(),
        sandbox=LocalSandbox(),
        protected=[],
    )


def test_a_tool_round_trip(project):
    first = reply(text("Looking."), tool_use("toolu_1", "read_file", path="README.md"), tool_use("toolu_2", "read_file", path=".env"))
    client = FakeClient([first, reply(text("Done."), stop_reason="end_turn")])

    outcome = run_agent(ClaudeLLM(client=client), gateway_for(project), "read the readme")

    assert outcome.stop_reason == "finished" and outcome.final_text == "Done."
    assert [r.decision.allowed for r in outcome.results] == [True, False]

    opening, followup = client.requests
    assert opening["model"] == DEFAULT_MODEL
    assert opening["messages"] == [{"role": "user", "content": "read the readme"}]
    assert {tool["name"] for tool in opening["tools"]} == {"read_file", "write_file", "delete_file", "list_dir", "run", "http_get"}

    assistant_turn, results = followup["messages"][1:]
    assert assistant_turn == {"role": "assistant", "content": first.content}, "sent back exactly as returned"
    assert results["role"] == "user"
    allowed, refused = results["content"]
    assert (allowed["tool_use_id"], allowed["is_error"]) == ("toolu_1", False) and "# calc" in allowed["content"]
    assert (refused["tool_use_id"], refused["is_error"]) == ("toolu_2", True) and "DENIED" in refused["content"]


def test_cli_run_supervises_the_model_and_prints_what_happened(project, monkeypatch, capsys):
    fake_sdk = SimpleNamespace(AnthropicError=type("AnthropicError", (Exception,), {}))
    monkeypatch.setitem(sys.modules, "anthropic", fake_sdk)  # CI does not install the real one
    replies = [reply(tool_use("toolu_1", "read_file", path=".env")), reply(text("Could not read it."), stop_reason="end_turn")]
    monkeypatch.setattr("aegis.llm.claude.ClaudeLLM", lambda model: ClaudeLLM(client=FakeClient(replies)))
    monkeypatch.setattr("aegis.session.new_state_dir", lambda: project.state_dir)

    assert cli(["run", "read the env file", "--workspace", str(project.workspace)]) == 0

    out = capsys.readouterr().out
    assert "DENY   read_file(.env)  [policy:**/.env]" in out
    assert "Could not read it." in out and "session: completed" in out
    assert cli(["verify", str(project.state_dir)]) == 0


def test_tool_calls_in_a_turn_that_did_not_end_normally_are_not_run(project):
    # A reply cut off by the output limit, or refused, can carry a half-formed call.
    for stop_reason in ("max_tokens", "refusal"):
        cut_off = reply(tool_use("toolu_9", "write_file", path="src/x.py", content="x = 1\n"), stop_reason=stop_reason)
        outcome = run_agent(ClaudeLLM(client=FakeClient([cut_off])), gateway_for(project), "task")
        assert outcome.results == [] and stop_reason in outcome.final_text
    assert not (project.workspace / "src" / "x.py").exists()
