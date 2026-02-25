import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from org.xyz.backslash.api.routes import graph, health, nodes
from org.xyz.backslash.core.config import get_settings
from org.xyz.backslash.core.logging import configure_logging

settings = get_settings()


def create_app() -> FastAPI:
    configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.app_version,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(graph.router)
    app.include_router(nodes.router)

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host=settings.host, port=settings.port)
