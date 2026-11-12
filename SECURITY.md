# Security

Aegis is a research prototype. Do not rely on it as the only thing standing
between an agent and a machine you care about.

## What counts as a vulnerability

Anything that lets an untrusted tool call do something the policy and the monitor
were supposed to stop, and that is **not** already listed under
[Known gaps](README.md#known-gaps). For example:

- a path that escapes the workspace,
- a tool call that runs without a monitor verdict,
- an edit to a sealed audit log that `aegis verify` accepts without the key,
- an encoding of a planted secret that the canary check claims to cover and misses.

The local sandbox not being an isolation boundary is a known gap, not a report.

## Reporting

Use GitHub's private vulnerability reporting (Security tab, "Report a
vulnerability") if it is enabled on this repository. Otherwise open an issue that
says a security report is waiting, without the details, and you will be contacted.

The most useful report is a new entry for the attack catalogue in
[`src/aegis/redteam/attacks.py`](src/aegis/redteam/attacks.py): a script of tool
calls and a predicate that shows what happened in the world. If `aegis redteam`
prints `succeeded` for it, that is the proof.
