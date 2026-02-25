from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from org.xyz.backslash.core.config import get_settings
from org.xyz.backslash.services.graph_query import GraphQueryService
from org.xyz.backslash.services.graph_repository import GraphLoader, GraphRepository, JsonFileLoader


@lru_cache
def get_loader() -> GraphLoader:
    return JsonFileLoader(get_settings().data_file)


@lru_cache
def get_repository(
    loader: Annotated[GraphLoader, Depends(get_loader)],
) -> GraphRepository:
    return GraphRepository(loader)


def get_query_service(
    repo: Annotated[GraphRepository, Depends(get_repository)],
) -> GraphQueryService:
    return GraphQueryService(repo)