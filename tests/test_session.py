"""End to end: a real monitor process, a real gateway, a scripted agent."""

import base64
import json

import pytest

from aegis.agent import run_agent
from aegis.audit import read_records
from aegis.cli import main as cli
from aegis.llm.scripted import ScriptedLLM, call
from aegis.session import Session, make_canary
from aegis.types import ToolCall, Verdict


def open_session(project, profile="default", **kwargs):
    return Session(
        project.workspace,
        project.policy(profile),
        state_dir=project.state_dir,
        policy_path=project.policy_path(profile),
        **kwargs,
    )


def test_a_normal_run_is_logged_sealed_and_verifiable(project):
    moves = [
        [call("read_file", path="src/calc.py")],
        [call("write_file", path="src/calc.py", content="def add(a, b):\n    return a + b\n\n\nVERSION = 2\n")],
        [call("run", argv=["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"])],
        [call("write_file", path="setup.cfg", content="[x]\n")],
    ]
    with open_session(project) as session:
        outcome = run_agent(ScriptedLLM(moves), session.gateway, "bump the version")

    assert outcome.stop_reason == "finished"
    assert [r.decision.allowed for r in outcome.results] == [True, True, True, False]
    assert "1 passed" in outcome.results[2].output
    assert outcome.results[3].decision.source == "policy"
    assert "VERSION = 2" in (project.workspace / "src" / "calc.py").read_text(encoding="utf-8")
    assert not (project.workspace / "setup.cfg").exists()

    report = session.report
    assert report.outcome == "completed" and report.sealed
    check = report.verify()
    assert check.ok and check.head == report.head and check.records == report.records

    kinds = [record["kind"] for record in read_records(report.log_path)]
    assert kinds == ["session_start", *["tool_call", "tool_result"] * 3, "tool_call", "seal"]
    start = read_records(report.log_path)[0]["payload"]
    assert start["policy_digest"] == project.policy().digest


def test_editing_the_log_afterwards_is_caught(project):
    with open_session(project) as session:
        session.gateway.execute(call("read_file", path="../state/audit.jsonl"))
        session.gateway.execute(call("read_file", path="README.md"))
    report = session.report
    assert report.verify().ok

    lines = report.log_path.read_text(encoding="ascii").splitlines()
    assert json.loads(lines[1])["payload"]["decision"]["rule"] == "tamper"
    pristine = "\n".join(lines) + "\n"

    report.log_path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="ascii", newline="\n")
    assert not report.verify().ok, "dropping the incriminating record must not verify"
    assert cli(["verify", str(project.state_dir)]) == 1

    report.log_path.write_text(pristine, encoding="ascii", newline="\n")
    assert cli(["verify", str(project.state_dir)]) == 0
    assert cli(["verify", str(project.state_dir), "--expect-head", report.head]) == 0
    assert cli(["verify", str(project.state_dir), "--expect-head", "0" * 64]) == 1


def test_no_monitor_means_no_tool_calls(project):
    with open_session(project) as session:
        assert session.gateway.execute(call("read_file", path="README.md")).ok
        session.monitor.proc.kill()
        session.monitor.proc.wait(5)

        refused = session.gateway.execute(call("write_file", path="src/after.py", content="x = 1\n"))
        assert refused.decision.verdict is Verdict.HALT
        assert refused.decision.rule == "monitor-unreachable"
        assert session.gateway.halted
        again = session.gateway.execute(call("read_file", path="README.md"))
        assert again.decision.rule == "halted"

    assert not (project.workspace / "src" / "after.py").exists()
    assert session.report.outcome == "halted"
    assert not session.report.sealed
    assert not session.report.verify().ok, "an unsealed log must not pass as a finished session"


def test_a_halt_stops_everything_that_follows(project):
    canary = make_canary()
    with open_session(project, "permissive", canaries=[canary]) as session:
        leak = session.gateway.execute(call("write_file", path="src/notes.py", content=f"KEY = '{canary}'\n"))
        assert leak.decision.verdict is Verdict.HALT and leak.decision.rule == "canary"
        later = session.gateway.execute(call("read_file", path="README.md"))
        assert not later.ok and later.decision.verdict is Verdict.HALT

    assert not (project.workspace / "src" / "notes.py").exists()
    assert session.report.outcome == "halted" and session.report.summary["halted"]
    assert canary not in session.report.log_path.read_text(encoding="ascii"), "the log must not hold the secret"
    assert session.report.verify().ok


def test_secret_read_from_a_file_is_redacted_in_the_log(project):
    canary = make_canary()
    (project.workspace / "settings.txt").write_text(f"token={canary}\n", encoding="utf-8")
    with open_session(project, "permissive", canaries=[canary]) as session:
        result = session.gateway.execute(call("read_file", path="settings.txt"))
        assert canary in result.output, "the tool result itself is unchanged"
        blocked = session.gateway.execute(call("http_get", url="http://127.0.0.1:9/x"))
        assert blocked.decision.rule == "secret-in-context"
    text = session.report.log_path.read_text(encoding="ascii")
    assert canary not in text and "[planted-secret]" in text


def test_encoded_secrets_are_redacted_too(project):
    canary = make_canary()
    encoded = base64.b64encode(canary.encode()).decode()
    with open_session(project, "permissive", canaries=[canary]) as session:
        leak = session.gateway.execute(call("http_get", url=f"http://127.0.0.1:9/c?d={encoded}"))
        assert leak.decision.rule == "canary"
    text = session.report.log_path.read_text(encoding="ascii")
    assert encoded not in text and "[planted-secret]" in text


def test_a_deleted_key_fails_verification(project):
    # Without the key only the hash chain is left, and a log rewritten from
    # scratch has a perfectly good chain.
    with open_session(project) as session:
        session.gateway.execute(call("read_file", path="README.md"))
    assert session.report.verify().ok
    (project.state_dir / "audit.key").unlink()
    assert not session.report.verify().ok
    assert cli(["verify", str(project.state_dir)]) == 1


def test_unknown_tools_and_bad_arguments_are_refused_and_logged(project):
    with open_session(project) as session:
        results = [
            session.gateway.execute(ToolCall("shell", {"cmd": "whoami"})),
            session.gateway.execute(ToolCall("read_file", {"path": 7})),
            session.gateway.execute(ToolCall("run", {"argv": "python -m pytest"})),
            session.gateway.execute(ToolCall("http_get", {"url": "file:///etc/passwd"})),
            session.gateway.execute(ToolCall("write_file", {"path": "src/x.py"})),
        ]
    assert [r.decision.rule for r in results] == [
        "unknown-tool", "bad-arguments", "bad-arguments", "bad-arguments", "bad-arguments",
    ]
    assert all(r.decision.source == "gateway" for r in results)
    assert session.report.records == 1 + len(results) + 1


def test_a_result_for_an_unreviewed_call_halts_the_session(project):
    with open_session(project) as session:
        ack = session.monitor.result("never-reviewed", True, "surprise")
        assert ack["halt"]
        refused = session.gateway.execute(call("read_file", path="README.md"))
        assert refused.decision.verdict is Verdict.HALT
    kinds = [record["kind"] for record in read_records(session.report.log_path)]
    assert "violation" in kinds


def test_state_dir_must_be_outside_the_workspace(project):
    inside = project.workspace / ".aegis"
    inside.mkdir()
    with pytest.raises(ValueError):
        Session(project.workspace, project.policy(), state_dir=inside)
    with pytest.raises(ValueError):
        Session(project.workspace, project.policy(), state_dir=project.workspace)


def test_redteam_refuses_to_run_without_pytest(monkeypatch, capsys):
    # Otherwise every attack that runs the fixture's tests would fail for the
    # wrong reason and be reported as blocked.
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    assert cli(["redteam", "--only", "budget_flood"]) == 2
    assert "pytest" in capsys.readouterr().err


def test_cli_log_prints_one_line_per_record(project, capsys):
    with open_session(project) as session:
        session.gateway.execute(call("read_file", path="README.md"))
    assert cli(["log", str(project.state_dir)]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == session.report.records
    assert "session_start" in lines[0] and "seal" in lines[-1]
