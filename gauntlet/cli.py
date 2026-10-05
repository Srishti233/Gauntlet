"""
Gauntlet CLI.

VERIFICATION STATUS: needs typer + pydantic + httpx, none installed in
this sandbox (no network access at write time -- see README
"Verification status"). Checked with `python -m py_compile` only. Run
`pytest tests/test_cli.py` after `pip install -e .[dev]` to confirm.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from gauntlet.attacks.loader import DEFAULT_SEEDS_PATH, validate_all
from gauntlet.mutations.engine import generate_variants
from gauntlet.reporting.report import render_markdown_report

app = typer.Typer(
    name="gauntlet",
    help="Red-teaming framework for LLM applications and agents.",
    add_completion=False,
)


@app.command("list-attacks")
def list_attacks(
    category: str | None = typer.Option(None, help="Filter by category."),
    seeds_path: Path = typer.Option(DEFAULT_SEEDS_PATH, help="Path to seeds.yaml."),
) -> None:
    """List seed attacks, optionally filtered by category."""
    entries = validate_all(seeds_path)
    if category:
        entries = [e for e in entries if e["category"] == category]
    for e in entries:
        typer.echo(f"{e['id']:35s} [{e['category']:28s}] {e['description']}")
    typer.echo(f"\n{len(entries)} attack(s) listed.")


@app.command("mutate")
def mutate(
    attack_id: str,
    depth: int = typer.Option(2, help="Max mutation composition depth."),
    budget: int = typer.Option(10, help="Max variants to show."),
    seed: int = typer.Option(1337, help="Determinism seed."),
    seeds_path: Path = typer.Option(DEFAULT_SEEDS_PATH, help="Path to seeds.yaml."),
) -> None:
    """Show mutated variants of a seed attack."""
    entries = validate_all(seeds_path)
    match = next((e for e in entries if e["id"] == attack_id), None)
    if match is None:
        typer.echo(f"No such attack id: {attack_id}", err=True)
        raise typer.Exit(code=1)

    variants = generate_variants(match["payload"], base_seed=seed, max_depth=depth, budget=budget)
    for v in variants:
        typer.echo(f"[{' -> '.join(v.lineage)}]")
        typer.echo(v.text[:300])
        typer.echo("-" * 40)
    typer.echo(f"{len(variants)} variant(s) shown (of up to {budget}).")


@app.command("report")
def report(results_path: Path) -> None:
    """Render a results.json file to markdown and print it."""
    data = json.loads(results_path.read_text(encoding="utf-8"))
    md = render_markdown_report(data)
    typer.echo(md)


@app.command("run")
def run(
    config: Path = typer.Option(..., "--config", help="Path to run.yaml."),
) -> None:
    """Run the full attack campaign against the targets in a run config."""
    from gauntlet.config import load_run_config
    from gauntlet.runner import execute_run  # local import: needs httpx/pydantic

    run_config = load_run_config(config)
    results = asyncio.run(execute_run(run_config))

    out_path = Path("results.json")
    out_path.write_text(results.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Wrote {out_path}")


@app.command("demo")
def demo() -> None:
    """Run the full unprotected-vs-Aegis comparison against the bundled
    compose stack and print the report path. Requires the services from
    docker-compose.yml to already be up (see `make demo`).
    """
    config_path = Path(__file__).resolve().parents[1] / "run.example.yaml"
    typer.echo(f"Using default demo config: {config_path}")
    run(config=config_path)


@app.command("export-misses")
def export_misses(
    results_path: Path,
    out_path: Path = typer.Option(Path("misses.jsonl"), help="Output JSONL path."),
) -> None:
    """Write every successful bypass as Aegis-format attacks.jsonl lines,
    split='discovered', for manual review before adding to Aegis's rules.
    """
    data = json.loads(results_path.read_text(encoding="utf-8"))
    lines = []
    for target_result in data.get("target_results", []):
        for attempt in target_result.get("attempts", []):
            if attempt.get("harm_success"):
                lines.append(
                    json.dumps(
                        {
                            "id": f"gauntlet_{attempt['attack_id']}_{target_result['target_name']}",
                            "category": attempt.get("category") or "unknown",
                            "variant": " -> ".join(attempt.get("lineage", [])) or "none",
                            "text": attempt["variant_text"],
                            "split": "discovered",
                        }
                    )
                )
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    header_path = out_path.with_suffix(".README.txt")
    header_path.write_text(
        "These lines were auto-discovered by Gauntlet and use split='discovered'\n"
        "so they are never accidentally mixed into Aegis's held-out test split.\n"
        "Review each one by hand before adding it to Aegis's training/eval rules.\n",
        encoding="utf-8",
    )
    typer.echo(f"Wrote {len(lines)} discovered bypass(es) to {out_path}")


@app.command("regress")
def regress(
    misses_path: Path = typer.Option(..., "--from", help="Path to a misses.jsonl file."),
    config: Path = typer.Option(..., "--config", help="Path to run.yaml for targets."),
) -> None:
    """Replay a saved set of bypasses against a target as a regression suite."""
    from gauntlet.config import load_run_config
    from gauntlet.runner import execute_regression  # local import: needs httpx/pydantic

    run_config = load_run_config(config)
    lines = [json.loads(line) for line in misses_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    results = asyncio.run(execute_regression(lines, run_config))
    typer.echo(json.dumps(results, indent=2))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
