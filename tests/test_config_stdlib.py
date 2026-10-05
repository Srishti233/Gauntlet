from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.config import load_raw_run_config, load_raw_targets
from gauntlet.targets.allowlist import is_host_allowed

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestRunConfigYaml(unittest.TestCase):
    def test_run_example_parses(self):
        cfg = load_raw_run_config(REPO_ROOT / "run.example.yaml")
        self.assertIn("seed", cfg)
        self.assertIn("targets", cfg)
        self.assertIsInstance(cfg["targets"], list)
        self.assertGreaterEqual(len(cfg["targets"]), 1)

    def test_run_example_targets_have_required_fields(self):
        cfg = load_raw_run_config(REPO_ROOT / "run.example.yaml")
        for t in cfg["targets"]:
            self.assertIn("name", t)
            self.assertIn("type", t)
            self.assertIn("base_url", t)

    def test_run_example_targets_pass_allowlist(self):
        cfg = load_raw_run_config(REPO_ROOT / "run.example.yaml")
        for t in cfg["targets"]:
            self.assertTrue(
                is_host_allowed(t["base_url"]),
                f"{t['name']} host should be allowed without override",
            )


class TestTargetsYaml(unittest.TestCase):
    def test_targets_example_parses(self):
        targets = load_raw_targets(REPO_ROOT / "targets.example.yaml")
        self.assertIsInstance(targets, list)
        self.assertGreaterEqual(len(targets), 1)

    def test_targets_example_all_allowed(self):
        targets = load_raw_targets(REPO_ROOT / "targets.example.yaml")
        for t in targets:
            self.assertTrue(is_host_allowed(t["base_url"]))


if __name__ == "__main__":
    unittest.main()
