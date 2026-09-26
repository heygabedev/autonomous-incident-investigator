from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from incident_investigator import __version__


def create_app() -> FastAPI:
    app = FastAPI(
        title="Autonomous Incident Investigator",
        version=__version__,
        docs_url="/docs",
        redoc_url=None,
    )

    @app.get("/api/v1/health/live", tags=["health"])
    async def liveness() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()


def run() -> None:
    uvicorn.run("incident_investigator.main:app", host="127.0.0.1", port=8000, reload=False)
