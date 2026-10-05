"""
Renders results into report.md.

``render_markdown_report`` takes plain dicts/lists (no pydantic
dependency) so it can be tested with only Jinja2 installed, which
genuinely is available in this sandbox (see README "Verification
status"). The CLI's `gauntlet report` command converts a RunResults
pydantic model into this same plain-dict shape via
``results_to_report_context`` before calling this function, so the one
rendering path is shared and tested either way.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader

_TEMPLATE = """\
# Gauntlet report

**Generated:** {{ generated_at }}
**Gauntlet version:** {{ gauntlet_version }}
**Seed:** {{ seed }}

## Summary

| Target | Evasion rate (95% CI) | Harm rate (95% CI) | N |
|---|---|---|---|
{% for t in targets -%}
| {{ t.name }} | {{ t.evasion_rate_str }} | {{ t.harm_rate_str }} | {{ t.n }} |
{% endfor %}

{% if comparison %}
## Protected vs unprotected

| Metric | Unprotected | Protected | Change |
|---|---|---|---|
| Evasion rate | {{ comparison.unprotected_evasion }} | {{ comparison.protected_evasion }} | {{ comparison.evasion_change }} |
| Harm rate | {{ comparison.unprotected_harm }} | {{ comparison.protected_harm }} | {{ comparison.harm_change }} |
{% endif %}

## Per-category results

{% for t in targets %}
### {{ t.name }}

| Category | N | Evasion | Harm | Mean requests to bypass |
|---|---|---|---|---|
{% for c in t.categories -%}
| {{ c.category }} | {{ c.n }} | {{ c.evasion_str }} | {{ c.harm_str }} | {{ c.mean_requests }} |
{% endfor %}
{% endfor %}

## Bypasses found

{% if bypasses %}
{% for b in bypasses %}
### {{ b.attack_id }} on {{ b.target_name }}

- **Category:** {{ b.category }}
- **Lineage:** {{ b.lineage | join(' -> ') }}
- **Attempts to bypass:** {{ b.attempts }}
- **Evidence:** {{ b.evidence }}

```
{{ b.payload }}
```
{% endfor %}
{% else %}
No bypasses found in this run.
{% endif %}

## What to fix

{% for rec in recommendations %}
- **{{ rec.category }}:** {{ rec.recommendation }}
{% endfor %}

## Run metadata

- Budgets: {{ budgets }}
- Targets: {{ target_descriptions }}
- Started: {{ started_at }}
- Finished: {{ finished_at }}
"""

_DEFENSIVE_RECOMMENDATIONS: dict[str, str] = {
    "instruction_override": "Detect and strip phrases that claim to override, ignore, or disregard prior instructions; treat them as high-risk regardless of phrasing.",
    "system_prompt_extraction": "Never let the model echo its own system prompt verbatim; filter outputs that closely match known system-prompt content.",
    "role_jailbreak": "Flag persona-adoption language ('you are now X with no restrictions') as a high-risk signal independent of topic.",
    "delimiter_injection": "Strip or escape user-supplied text that mimics chat-template delimiters or system/developer role markers before building the prompt.",
    "tool_hijacking": "Validate tool-call arguments against an allowlist server-side; never trust argument values suggested by untrusted message content.",
    "indirect_injection": "Treat all tool/document/webpage content as untrusted data, never as instructions, and label it clearly in the prompt structure.",
    "multilingual": "Run injection detection on a language-normalized (translated or multilingual-embedding) representation of the input, not just the raw English-tuned classifier.",
    "encoded_payload": "Decode common encodings (base64, hex, rot13, URL-encoding) before running injection classifiers, so encoded payloads can't skip detection.",
    "long_context": "Scan the full context window for injection patterns, not just the first/last N tokens; padding attacks rely on truncated scanning.",
    "tool_misuse": "Require explicit user confirmation for any tool call with side effects (sending data, spending money) when arguments were influenced by model-generated or retrieved content.",
    "data_exfiltration": "Block outbound requests and markdown/image URLs to domains not on an explicit allowlist; redact secrets before they reach model output.",
    "goal_hijack": "Pin the agent's task definition outside the mutable conversation history, and re-validate each step against the original user goal.",
}


def recommendations_for_categories(categories: list[str]) -> list[dict[str, str]]:
    return [
        {
            "category": c,
            "recommendation": _DEFENSIVE_RECOMMENDATIONS.get(
                c, "Review this category's attempts manually; no canned recommendation yet."
            ),
        }
        for c in categories
    ]


def render_markdown_report(context: dict[str, Any]) -> str:
    env = Environment(loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True)
    template = env.from_string(_TEMPLATE)
    return template.render(**context)


def write_markdown_report(context: dict[str, Any], out_path: Path | str) -> None:
    text = render_markdown_report(context)
    Path(out_path).write_text(text, encoding="utf-8")
