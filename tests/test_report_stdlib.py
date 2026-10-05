from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet.reporting.report import (
    recommendations_for_categories,
    render_markdown_report,
)
from gauntlet.reporting.stats import wilson_interval


def _sample_context() -> dict:
    evasion = wilson_interval(12, 25)
    harm = wilson_interval(4, 25)
    return {
        "generated_at": "2026-01-01T00:00:00Z",
        "gauntlet_version": "0.1.0",
        "seed": 1337,
        "targets": [
            {
                "name": "agent-unprotected",
                "evasion_rate_str": evasion.as_pct_string(),
                "harm_rate_str": harm.as_pct_string(),
                "n": 25,
                "categories": [
                    {
                        "category": "instruction_override",
                        "n": 5,
                        "evasion_str": wilson_interval(4, 5).as_pct_string(),
                        "harm_str": wilson_interval(2, 5).as_pct_string(),
                        "mean_requests": 3.2,
                    }
                ],
            }
        ],
        "comparison": {
            "unprotected_evasion": "48.0%",
            "protected_evasion": "12.0%",
            "evasion_change": "-36.0pp",
            "unprotected_harm": "16.0%",
            "protected_harm": "4.0%",
            "harm_change": "-12.0pp",
        },
        "bypasses": [
            {
                "attack_id": "inst_override_basic_01",
                "target_name": "agent-unprotected",
                "category": "instruction_override",
                "lineage": ["enc_base64", "wrap_roleplay"],
                "attempts": 3,
                "evidence": "reply contained OVERRIDE ACCEPTED",
                "payload": "<example payload>",
            }
        ],
        "recommendations": recommendations_for_categories(["instruction_override"]),
        "budgets": "max_requests_per_seed=20",
        "target_descriptions": "agent-unprotected @ localhost:8001",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:05:00Z",
    }


class TestRenderMarkdownReport(unittest.TestCase):
    def test_renders_without_error(self):
        report = render_markdown_report(_sample_context())
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)

    def test_contains_target_name(self):
        report = render_markdown_report(_sample_context())
        self.assertIn("agent-unprotected", report)

    def test_contains_wilson_interval_formatted(self):
        report = render_markdown_report(_sample_context())
        self.assertIn("%", report)
        self.assertIn("[", report)

    def test_contains_bypass_lineage(self):
        report = render_markdown_report(_sample_context())
        self.assertIn("enc_base64 -> wrap_roleplay", report)

    def test_contains_recommendation(self):
        report = render_markdown_report(_sample_context())
        self.assertIn("instruction_override", report)
        self.assertIn("override", report.lower())

    def test_empty_bypasses_shows_none_found_message(self):
        ctx = _sample_context()
        ctx["bypasses"] = []
        report = render_markdown_report(ctx)
        self.assertIn("No bypasses found", report)

    def test_comparison_section_present_when_given(self):
        report = render_markdown_report(_sample_context())
        self.assertIn("Protected vs unprotected", report)

    def test_comparison_section_absent_when_none(self):
        ctx = _sample_context()
        ctx["comparison"] = None
        report = render_markdown_report(ctx)
        self.assertNotIn("Protected vs unprotected", report)


class TestRecommendations(unittest.TestCase):
    def test_known_category_gets_specific_recommendation(self):
        recs = recommendations_for_categories(["data_exfiltration"])
        self.assertEqual(len(recs), 1)
        self.assertIn("allowlist", recs[0]["recommendation"].lower())

    def test_unknown_category_gets_fallback_text(self):
        recs = recommendations_for_categories(["totally_unknown_category"])
        self.assertIn("no canned recommendation", recs[0]["recommendation"].lower())

    def test_covers_all_twelve_categories(self):
        categories = [
            "instruction_override",
            "system_prompt_extraction",
            "role_jailbreak",
            "delimiter_injection",
            "tool_hijacking",
            "indirect_injection",
            "multilingual",
            "encoded_payload",
            "long_context",
            "tool_misuse",
            "data_exfiltration",
            "goal_hijack",
        ]
        recs = recommendations_for_categories(categories)
        for rec in recs:
            self.assertNotIn("no canned recommendation", rec["recommendation"].lower())


if __name__ == "__main__":
    unittest.main()
