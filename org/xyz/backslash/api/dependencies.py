from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from org.xyz.backslash.core.config import get_settings
from org.xyz.backslash.services.graph_query import GraphQueryService
from org.xyz.backslash.services.graph_repository import GraphRepository


@lru_cache
def get_repository() -> GraphRepository:
    return GraphRepository.from_file(get_settings().data_file)


def get_query_service(
    repo: Annotated[GraphRepository, Depends(get_repository)],
) -> GraphQueryService:
    return GraphQueryService(repo)
