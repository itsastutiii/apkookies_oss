"""Repository config files parse (a broken workflow only shows up after a push)."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflow_is_valid_yaml():
    wf = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert "python" in wf["jobs"]
    for job in wf["jobs"].values():
        assert job["steps"], job


def test_config_yaml_files_parse():
    for p in (ROOT / "config").glob("*.yaml"):
        yaml.safe_load(p.read_text(encoding="utf-8"))
