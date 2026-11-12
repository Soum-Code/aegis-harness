from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import pytest

from aegis.policy import Policy


@dataclass
class Project:
    base: Path
    workspace: Path
    state_dir: Path

    def policy_path(self, profile: str = "default") -> Path:
        path = self.base / f"{profile}.toml"
        if not path.exists():
            text = resources.files("aegis").joinpath("policies", f"{profile}.toml").read_text(encoding="utf-8")
            path.write_text(text, encoding="utf-8")
        return path

    def policy(self, profile: str = "default") -> Policy:
        return Policy.load(self.policy_path(profile))


@pytest.fixture
def project(tmp_path):
    """A small working project, with a state directory beside the workspace."""
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "tests").mkdir()
    (workspace / "src" / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (workspace / "tests" / "test_calc.py").write_text(
        "from src.calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )
    (workspace / "README.md").write_text("# calc\n", encoding="utf-8")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return Project(tmp_path, workspace, state_dir)
