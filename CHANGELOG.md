# Changelog

## 0.1.0 (2026-11-10)

First version.

- Gateway with argument validation and path confinement, for tool paths and for
  path-like arguments of allowed commands.
- Default-deny capability policy in TOML.
- Monitor in its own process: canary, tamper, reward-hacking, secret-in-context,
  tainted-context and budget rules. Fails closed.
- Hash-chained, HMAC-signed, sealed audit log, with `aegis verify` and `aegis log`.
- Red-team suite of 30 scripted attacks across three profiles, with `aegis redteam`.
- Scripted model adapter and agent loop.

Known gaps are listed in the README.
