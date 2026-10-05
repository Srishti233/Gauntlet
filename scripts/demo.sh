#!/usr/bin/env bash
# Brings up the full Docker Compose stack (gullible-llm, both demo
# agents, Aegis + postgres + redis), waits for health checks, runs the
# full unprotected-vs-Aegis campaign, prints the report path, and tears
# the stack down. This is what `make demo` and the CI `demo` job call.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building and starting the stack..."
docker compose up --build -d --wait

echo "==> Running the Gauntlet demo campaign..."
gauntlet demo

echo "==> Done. See results.json and run 'gauntlet report results.json' for markdown."

echo "==> Tearing down..."
docker compose down -v
