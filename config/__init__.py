"""Config package: settings + YAML loaders."""
from __future__ import annotations

from pathlib import Path

import yaml

_CONFIG_DIR = Path(__file__).parent


def load_yaml(name: str) -> dict:
    """Load a YAML config file from the config/ directory."""
    with open(_CONFIG_DIR / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def thresholds() -> dict:
    return load_yaml("thresholds.yaml")


def data_sources() -> dict:
    return load_yaml("data_sources.yaml")
