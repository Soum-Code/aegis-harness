"""Command line entry point.

    aegis redteam                 run the attack suite (two guarded profiles and a baseline)
    aegis redteam --list          show the catalogue
    aegis verify <state_dir>      check a session's audit log
    aegis log <state_dir>         print a session's audit log, one line per record
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import read_records, verify_log
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
