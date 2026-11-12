# Contributing

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -m "not slow"             # a few seconds
pytest                           # everything, including the attack suite
```

The core has no runtime dependencies. Please keep it that way: every dependency
in the trusted part of the harness is something an attacker can aim at.

## Adding an attack

The attack catalogue is the most valuable part of this project. An attack is two
things, both in [`src/aegis/redteam/attacks.py`](src/aegis/redteam/attacks.py):

1. **Moves**: a function that takes the fixture (`Env`) and returns the tool
   calls a hostile model would make.
2. **A predicate**: a function that looks at the world afterwards and says
   whether the attacker got what it wanted. Did the secret reach the listener?
   Does the file exist? Do the weakened tests pass?

Then add an `Attack(...)` entry to `ATTACKS`.

Rules:

- **Judge by the world, not by the harness.** A predicate must never ask the
  harness whether it blocked something. It checks the effect.
- **Prove the attack is real.** Run `aegis redteam --profile no-monitor --only
  your_attack`. If it does not succeed with nothing guarding it, it is a broken
  script, not a blocked attack.
- **Do not hide successes.** If your attack gets through and you are not fixing
  it in the same change, mark it with `known_gap` and say why. It stays in the
  suite and counts against the attack success rate.
- **If you close a gap**, remove its `known_gap` marker and update the tables in
  the README. A test fails until you do.

## Changing the harness

- A change to the gateway, policy, monitor or audit log needs a test.
- `aegis redteam` must exit 0: no unexpected successes, no invalid logs.
- The monitor may tighten a policy decision. It must never loosen one.
- When in doubt, fail closed.
