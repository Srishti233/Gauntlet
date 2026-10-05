FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY gauntlet ./gauntlet
COPY services ./services
COPY README.md ./

RUN pip install --no-cache-dir -e ".[dev]"

ENTRYPOINT ["gauntlet"]
CMD ["--help"]
