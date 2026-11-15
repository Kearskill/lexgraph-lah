FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Copy project configuration and source tree required for editable/package build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY examples ./examples
COPY evals ./evals

# Install locked production dependencies without dev group
RUN uv sync --frozen --no-dev

EXPOSE 8000

# Run the FastAPI entrypoint (initializes Arize Phoenix OTel + starts uvicorn on 0.0.0.0:8000)
CMD ["uv", "run", "--no-dev", "lexgraph-lah"]
