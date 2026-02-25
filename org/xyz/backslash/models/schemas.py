from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityResponse(BaseModel):
    file: str | None = None
    severity: str
    message: str
    metadata: dict[str, str] = {}


class NodeResponse(BaseModel):
    name: str
    kind: str
    language: str | None = None
    path: str | None = None
    publicExposed: bool = False
    vulnerabilities: list[VulnerabilityResponse] = []
    metadata: dict[str, str] = {}


class EdgeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source: str = Field(serialization_alias="from")
    target: str = Field(serialization_alias="to")


class GraphResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    nodes: list[NodeResponse]
    edges: list[EdgeResponse]


class QueryMeta(BaseModel):
    total_paths: int
    active_filters: list[str]


class QueryResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    nodes: list[NodeResponse]
    edges: list[EdgeResponse]
    meta: QueryMeta


class NodeListResponse(BaseModel):
    nodes: list[NodeResponse]
    count: int


class FilterDoc(BaseModel):
    description: str
    values: str
    example: str


class FiltersResponse(BaseModel):
    filters: dict[str, FilterDoc]


class HealthResponse(BaseModel):
    status: str
