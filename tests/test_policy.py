from importlib import resources

import pytest

from aegis.policy import Policy, PolicyError
from aegis.types import Capability


@pytest.fixture(scope="module")
def default_policy(tmp_path_factory):
    path = tmp_path_factory.mktemp("policy") / "default.toml"
    path.write_text(
        resources.files("aegis").joinpath("policies", "default.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return Policy.load(path)


def test_load_records_a_digest(default_policy):
    assert len(default_policy.digest) == 64
    assert default_policy.limits.max_tool_calls == 60


def test_empty_policy_denies_everything():
    policy = Policy.from_dict({"version": 1})
    assert not policy.check_path(Capability.FS_READ, "README.md").allowed
    assert not policy.check_exec(["python", "-m", "pytest"]).allowed
    assert not policy.check_host("example.com").allowed
    assert policy.check_path(Capability.FS_READ, "README.md").rule == "default-deny"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"version": 2},
        {"version": 1, "limits": {"max_tool_calls": 5, "surprise": 1}},
        {"version": 1, "fs": {"read": {"allow": "**"}}},
        {"version": 1, "fs": "everything"},
        {"version": 1, "proc": {"exec": {"allow": [[]]}}},
        {"version": 1, "proc": {"exec": {"allow": "python"}}},
        {"version": 1, "net": {"http": {"allow": [1]}}},
    ],
)
def test_malformed_policies_are_rejected(data):
    with pytest.raises(PolicyError):
        Policy.from_dict(data)


def test_unparseable_file_is_rejected(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("version = = 1", encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.load(path)


def test_reads_are_wide_but_secrets_are_denied(default_policy):
    assert default_policy.check_path(Capability.FS_READ, "src/calc.py").allowed
    for secret in (".env", ".ENV", "config/.env", ".env.local", "certs/server.PEM", "id_rsa", ".git/config"):
        assert not default_policy.check_path(Capability.FS_READ, secret).allowed, secret


def test_writes_are_narrow(default_policy):
    assert default_policy.check_path(Capability.FS_WRITE, "src/calc.py").allowed
    assert default_policy.check_path(Capability.FS_WRITE, "tests/test_calc.py").allowed
    assert default_policy.check_path(Capability.FS_WRITE, "NOTES.md").allowed
    for path in ("pytest.ini", "pyproject.toml", "tests/conftest.py", "conftest.py", "src/.env", "docs/guide.md"):
        assert not default_policy.check_path(Capability.FS_WRITE, path).allowed, path


def test_nothing_can_be_deleted(default_policy):
    assert not default_policy.check_path(Capability.FS_DELETE, "tests/test_calc.py").allowed


def test_deny_wins_over_allow():
    policy = Policy.from_dict({"version": 1, "fs": {"write": {"allow": ["**"], "deny": ["**/secret.txt"]}}})
    assert policy.check_path(Capability.FS_WRITE, "a/b.txt").allowed
    decision = policy.check_path(Capability.FS_WRITE, "a/SECRET.txt")
    assert not decision.allowed and decision.rule == "**/secret.txt"


def test_exec_rules_match_whole_argv(default_policy):
    assert default_policy.check_exec(["python", "-m", "pytest"]).allowed
    assert default_policy.check_exec(["python", "-m", "pytest", "-q", "tests"]).allowed
    assert default_policy.check_exec(["Python.EXE", "-m", "pytest"]).allowed
    for argv in (
        ["python"],
        ["python", "-c", "print(1)"],
        ["python", "-m", "pip", "install", "x"],
        ["pytest"],
        ["bash", "-c", "python -m pytest"],
        ["./python", "-m", "pytest"],
        ["C:\\evil\\python.exe", "-m", "pytest"],
        [],
        ["python", ""],
        ["python", 3],
    ):
        assert not default_policy.check_exec(argv).allowed, argv


def test_exec_rule_without_tail_is_exact():
    policy = Policy.from_dict({"version": 1, "proc": {"exec": {"allow": [["git", "status"]]}}})
    assert policy.check_exec(["git", "status"]).allowed
    assert not policy.check_exec(["git", "status", "--short"]).allowed
    assert not policy.check_exec(["git"]).allowed


def test_hosts():
    policy = Policy.from_dict({"version": 1, "net": {"http": {"allow": ["api.example.com", "*.internal"]}}})
    assert policy.check_host("api.example.com").allowed
    assert policy.check_host("API.Example.com.").allowed
    assert policy.check_host("db.internal").allowed
    assert not policy.check_host("example.com").allowed
    assert not policy.check_host("api.example.com.evil.net").allowed
