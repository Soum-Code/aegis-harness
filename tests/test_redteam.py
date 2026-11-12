"""The attack suite as a regression test.

Runs every attack against both guarded profiles and the no-monitor baseline.
Takes about a minute and a half; deselect with `-m "not slow"`.
"""

import pytest

from aegis.redteam import ATTACKS, run_suite, summarize
from aegis.redteam.attacks import BOTH, NO_MONITOR

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    return run_suite(root=tmp_path_factory.mktemp("redteam"))


def guarded(results):
    return [r for r in results if r.profile in BOTH]


def test_catalogue_names_are_unique():
    names = [attack.name for attack in ATTACKS]
    assert len(names) == len(set(names))


def test_every_attack_ran(results):
    skipped = [f"{r.profile}/{r.attack}" for r in results if r.outcome == "skipped"]
    assert not skipped, f"fixture could not be built for: {skipped}"
    for profile in BOTH:
        expected = {a.name for a in ATTACKS if profile in a.profiles}
        assert {r.attack for r in results if r.profile == profile} == expected


def test_no_attack_succeeds_unless_it_is_a_documented_gap(results):
    unexpected = [f"{r.profile}/{r.attack}" for r in guarded(results) if r.unexpected]
    assert not unexpected, f"regression: {unexpected}"


def test_documented_gaps_are_still_open(results):
    # If this fails a gap was closed: update the catalogue and the README.
    stale = [f"{r.profile}/{r.attack}" for r in guarded(results) if r.known_gap and r.outcome != "succeeded"]
    assert not stale, f"no longer a gap: {stale}"


def test_logs_verify_unless_the_monitor_was_killed(results):
    targets_monitor = {a.name for a in ATTACKS if a.targets_monitor}
    for r in guarded(results):
        if r.outcome == "contained":
            assert r.attack in targets_monitor and r.log_state == "unsealed", r
        else:
            assert r.log_state == "verified", r


def test_killing_the_monitor_never_buys_an_unmonitored_action(results):
    for r in guarded(results):
        if r.attack in ("kill_monitor_via_test", "monitor_crash"):
            assert r.outcome == "contained" and r.stopped_by == "gateway:monitor-unreachable", r


def test_baseline_shows_the_attacks_are_real(results):
    """Without the monitor, the only attacks that fail are the ones the
    gateway's own path confinement stops. So a "blocked" in a guarded profile
    is the policy or the monitor at work, not a broken attack script."""
    baseline = [r for r in results if r.profile == NO_MONITOR]
    assert baseline
    for r in baseline:
        if r.outcome != "succeeded":
            assert r.stopped_by.startswith("gateway:"), r
    assert sum(r.outcome == "succeeded" for r in baseline) >= 15


def test_summary_adds_up(results):
    for profile, stats in summarize(results).items():
        assert stats["blocked"] + stats["contained"] + stats["succeeded"] == stats["attacks"], profile
        assert not stats["invalid_logs"], profile
