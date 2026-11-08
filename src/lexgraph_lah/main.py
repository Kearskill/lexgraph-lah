import uvicorn
from fastapi import FastAPI

from lexgraph_lah.api.routes import router
from lexgraph_lah.config import settings
from lexgraph_lah.telemetry.tracer import telemetry_registry


def create_app() -> FastAPI:
    app = FastAPI(
        title="lexgraph-lah",
        description=(
            "Point-in-Time Legal Graph-RAG, Automated Entity/Citation Verification, "
            "and FinOps-Instrumented Compliance Engine"
        ),
        version="0.1.0",
    )
    app.include_router(router)
    return app


app = create_app()


def main() -> None:
    telemetry_registry.init_otel(endpoint=settings.phoenix_collector_endpoint)
    uvicorn.run("lexgraph_lah.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    main()
