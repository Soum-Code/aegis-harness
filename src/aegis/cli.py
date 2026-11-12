"""Command line entry point.

    aegis redteam                 run the attack suite (two guarded profiles and a baseline)
    aegis redteam --list          show the catalogue
    aegis run "<task>"            run Claude on a task under the harness
    aegis verify <state_dir>      check a session's audit log
    aegis log <state_dir>         print a session's audit log, one line per record
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from . import __version__
from .audit import read_records, verify_log
from .llm.claude import DEFAULT_MODEL
from .monitor import AUDIT_FILE, KEY_FILE


def _cmd_redteam(args: argparse.Namespace) -> int:
    from .redteam import ATTACKS, format_table, run_suite, summarize, to_json
    from .redteam.runner import ALL_PROFILES

    if args.list:
        for attack in ATTACKS:
            gaps = f"  [known gap: {', '.join(attack.known_gap)}]" if attack.known_gap else ""
            print(f"{attack.category:15} {attack.name:22} {attack.goal}{gaps}")
        return 0

    known = {attack.name for attack in ATTACKS}
    unknown = sorted(set(args.only or []) - known)
    if unknown:
        print(f"unknown attack(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    if importlib.util.find_spec("pytest") is None:
        # Without it every attack that runs the fixture's tests fails for the
        # wrong reason and would be counted as blocked.
        print("the attack suite runs pytest inside its fixture project: pip install pytest", file=sys.stderr)
        return 2

    profiles = ALL_PROFILES if args.profile == "all" else (args.profile,)
    results = run_suite(profiles, args.only)
    print(format_table(results))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(to_json(results), indent=2) + "\n", encoding="utf-8")
        print(f"\nreport written to {args.json}")

    stats = summarize(results).values()
    regressions = [name for s in stats for name in s["succeeded_unexpected"]]
    bad_logs = [name for s in stats for name in s["invalid_logs"]]
    closed = [name for s in stats for name in s["gaps_now_closed"]]
    if closed:
        print(f"\nknown gaps that did not succeed (update the catalogue): {', '.join(sorted(set(closed)))}")
    if regressions or bad_logs:
        print(f"\nFAIL  unexpected successes: {regressions or 'none'}; invalid logs: {bad_logs or 'none'}")
        return 1
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        import anthropic
    except ImportError:
        print('aegis run needs the Anthropic SDK: pip install "aegis-harness[claude]"', file=sys.stderr)
        return 2
    from .agent import run_agent
    from .llm.claude import ClaudeLLM
    from .policy import Policy
    from .session import Session

    policy_path = Path(args.policy) if args.policy else Path(__file__).parent / "policies" / "default.toml"
    session = Session(Path(args.workspace), Policy.load(policy_path), policy_path=policy_path)
    try:
        with session:
            outcome = run_agent(ClaudeLLM(model=args.model), session.gateway, args.task)
    except anthropic.AnthropicError as exc:
        print(f"Claude API error: {exc}\naudit log: {session.state_dir}", file=sys.stderr)
        return 1

    calls = {c.call_id: c for entry in outcome.transcript if entry["role"] == "assistant" for c in entry["calls"]}
    for result in outcome.results:
        call, decision = calls[result.call_id], result.decision
        target = call.args.get("path") or call.args.get("url") or call.args.get("argv", "")
        by = "" if decision.allowed else f"  [{decision.source}:{decision.rule}]"
        print(f"{decision.verdict.value.upper():5}  {call.tool}({target}){by}")

    report = session.report
    print(f"\n{outcome.final_text}\n")
    print(f"agent stopped: {outcome.stop_reason}; session: {report.outcome}")
    print(f"audit log: {report.state_dir}")
    if report.sealed:
        print(f"verify with: aegis verify {report.state_dir} --expect-head {report.head}")
    return 0 if outcome.stop_reason == "finished" else 1


def _cmd_verify(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    log_path = state_dir / AUDIT_FILE
    if not log_path.exists():
        print(f"no audit log at {log_path}", file=sys.stderr)
        return 2
    key_path = state_dir / KEY_FILE
    if not key_path.exists():
        # The hash chain alone proves nothing here: whoever rewrote the file
        # could rebuild a consistent chain. Only the MACs need the key.
        print(f"FAIL  no key file at {key_path}: the record MACs cannot be checked")
        return 1
    report = verify_log(log_path, key_path.read_bytes(), require_seal=not args.allow_unsealed)
    if report.ok:
        print(f"OK  {report.records} records, sealed={report.sealed}, head={report.head}")
        if args.expect_head and args.expect_head != report.head:
            print(f"FAIL  head does not match the expected {args.expect_head}")
            return 1
        return 0
    print(f"FAIL  {report.error} (after {report.records} good records)")
    return 1


def _cmd_log(args: argparse.Namespace) -> int:
    log_path = Path(args.state_dir) / AUDIT_FILE
    if not log_path.exists():
        print(f"no audit log at {log_path}", file=sys.stderr)
        return 2
    for record in read_records(log_path):
        payload = json.dumps(record.get("payload", {}), ensure_ascii=True)
        if len(payload) > args.width:
            payload = payload[: args.width - 3] + "..."
        print(f"{record.get('seq', '?'):>4}  {record.get('kind', '?'):10}  {payload}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="A tamper-resistant harness for LLM agents: run the attack suite, verify and read audit logs.",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    redteam = sub.add_parser("redteam", help="run the attack suite")
    redteam.add_argument("--profile", choices=("default", "permissive", "no-monitor", "all"), default="all")
    redteam.add_argument("--only", nargs="+", metavar="ATTACK", help="run only these attacks")
    redteam.add_argument("--json", metavar="PATH", help="also write the results as JSON")
    redteam.add_argument("--list", action="store_true", help="list the attacks and exit")
    redteam.set_defaults(func=_cmd_redteam)

    run = sub.add_parser("run", help="run Claude on a task under the harness")
    run.add_argument("task", help="what the agent should do")
    run.add_argument("--workspace", default=".", help="project directory the agent works in (default: here)")
    run.add_argument("--policy", metavar="FILE", help="policy file (default: the shipped default policy)")
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.set_defaults(func=_cmd_run)

    verify = sub.add_parser("verify", help="verify a session's audit log")
    verify.add_argument("state_dir")
    verify.add_argument("--allow-unsealed", action="store_true", help="accept a log with no seal record")
    verify.add_argument("--expect-head", metavar="HASH", help="head hash recorded when the session ended")
    verify.set_defaults(func=_cmd_verify)

    log = sub.add_parser("log", help="print a session's audit log")
    log.add_argument("state_dir")
    log.add_argument("--width", type=int, default=160)
    log.set_defaults(func=_cmd_log)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
