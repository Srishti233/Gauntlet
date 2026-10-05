.PHONY: install test test-stdlib lint demo toy-demo clean

install:
	pip install -e ".[dev]"

# The subset of tests that run with only the Python standard library
# plus PyYAML and Jinja2 (no pydantic/httpx/fastapi/typer required).
# Useful for verifying the core logic without a full install.
test-stdlib:
	python3 -m unittest discover -s tests -p "test_*_stdlib.py" -v

test:
	pytest -v --cov=gauntlet --cov-report=term-missing

lint:
	ruff check gauntlet services tests

toy-demo:
	python3 scripts/toy_demo.py

demo:
	docker compose up --build -d --wait
	gauntlet demo
	docker compose logs --tail=200
	docker compose down -v

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name "__pycache__" -type d -exec rm -rf {} +
