import os

import pytest

from aegis.paths import PathEscape, confine, glob_match, matches_any, relative_posix


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    return root


def test_plain_paths_resolve_inside(workspace):
    assert confine(workspace, "src/app.py") == (workspace / "src" / "app.py").resolve()
    assert confine(workspace, "src\\app.py") == (workspace / "src" / "app.py").resolve()
    assert confine(workspace, ".") == workspace.resolve()
    assert confine(workspace, "src/../README.md") == (workspace / "README.md").resolve()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "../outside/a.txt",
        "src/../../outside/a.txt",
        "src\\..\\..\\outside\\a.txt",
        "/etc/passwd",
        "\\\\server\\share\\x",
        "C:/Windows/win.ini",
        "C:secret.txt",
        "src/app.py:stream",
        "src/app.py.",
        "src/app.py ",
        "src./app.py",
        "NUL",
        "src/con.txt",
        "COM1",
        "src/a\x00.py",
    ],
)
def test_escapes_and_aliases_are_rejected(workspace, bad):
    with pytest.raises(PathEscape):
        confine(workspace, bad)


def test_link_out_of_the_workspace_is_rejected(workspace, tmp_path):
    link = workspace / "link"
    try:
        if os.name == "nt":
            import _winapi

            _winapi.CreateJunction(str(tmp_path / "outside"), str(link))
        else:
            os.symlink(tmp_path / "outside", link, target_is_directory=True)
    except (OSError, ImportError, AttributeError):
        pytest.skip("cannot create a directory link here")
    with pytest.raises(PathEscape):
        confine(workspace, "link/a.txt")


def test_relative_posix(workspace):
    assert relative_posix(workspace, workspace / "src" / "app.py") == "src/app.py"
    assert relative_posix(workspace, workspace) == "."


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**", "a/b/c.py", True),
        ("**", ".", True),
        ("src/**", "src/a/b.py", True),
        ("src/**", "srcx/a.py", False),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("**/.env", ".env", True),
        ("**/.env", "a/b/.env", True),
        ("**/.env", "a/.envrc", False),
        ("**/*.key", "keys/server.key", True),
        ("src/?.py", "src/a.py", True),
        ("src/?.py", "src/ab.py", False),
        ("a+b.txt", "a+b.txt", True),
        ("a+b.txt", "aab.txt", False),
    ],
)
def test_glob_match(pattern, path, expected):
    assert glob_match(pattern, path, ignore_case=False) is expected


def test_glob_case_is_a_choice():
    assert not glob_match("**/.env", ".ENV", ignore_case=False)
    assert glob_match("**/.env", ".ENV", ignore_case=True)
    assert matches_any(["*.md", "**/.env"], "x/.EnV", ignore_case=True) == "**/.env"
    assert matches_any(["*.md"], "x.py", ignore_case=True) is None
