"""
Loading and validating run.yaml / targets.yaml.

``load_run_config`` returns a validated ``gauntlet.models.RunConfig``
(needs pydantic). ``load_raw_run_config`` / ``load_raw_targets`` return
plain dicts from YAML with no pydantic dependency, used by this
sandbox's stdlib tests to prove the YAML files themselves parse and
have the expected shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_raw_run_config(path: Path | str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: run config must be a YAML mapping")
    return data


def load_raw_targets(path: Path | str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict) and "targets" in data:
        data = data["targets"]
    if not isinstance(data, list):
        raise ValueError(f"{path}: targets file must be a YAML list (or {{targets: [...]}})")
    return data


def load_run_config(path: Path | str):
    """Load and validate run.yaml into a RunConfig. Requires pydantic."""
    from gauntlet.models import RunConfig  # local import: optional dep

    raw = load_raw_run_config(path)
    return RunConfig(**raw)
