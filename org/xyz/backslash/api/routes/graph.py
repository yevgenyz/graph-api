from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from org.xyz.backslash.api.dependencies import get_query_service
from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.models.schemas import (
    FilterDoc,
    FiltersResponse,
    GraphResponse,
    QueryResponse,
)
from org.xyz.backslash.services.filters import FilterParams
from org.xyz.backslash.services.graph_query import GraphQueryService

router = APIRouter(prefix="/api/graph", tags=["Graph"])

_FILTER_DOCS: dict[str, FilterDoc] = {
    "starts_from_public": FilterDoc(
        description="Include only paths whose first node has publicExposed=true.",
        values="true | false",
        example="?starts_from_public=true",
    ),
    "ends_at_sink": FilterDoc(
        description="Include only paths whose last node is a sink (rds/sqs).",
        values="true | false",
        example="?ends_at_sink=true",
    ),
    "has_vulnerability": FilterDoc(
        description="Include only paths where at least one node has a vulnerability.",
        values="true | false",
        example="?has_vulnerability=true",
    ),
    "vulnerability_severity": FilterDoc(
        description="Narrow has_vulnerability to a specific severity (requires has_vulnerability=true).",
        values=" | ".join(s.value for s in VulnerabilitySeverity),
        example="?has_vulnerability=true&vulnerability_severity=high",
    ),
    "node_kind": FilterDoc(
        description="Include only paths that contain at least one node of the given kind.",
        values="service | rds | sqs | ...",
        example="?node_kind=rds",
    ),
}


@router.get("/filters", response_model=FiltersResponse, tags=["Filters"])
def list_filters() -> FiltersResponse:
    """Return documentation for all available query filter parameters."""
    return FiltersResponse(filters=_FILTER_DOCS)


@router.get("", response_model=GraphResponse)
def full_graph(
    svc: Annotated[GraphQueryService, Depends(get_query_service)],
) -> JSONResponse:
    """Return the complete graph (all nodes and direct edges)."""
    result = svc.full_graph()
    return JSONResponse(
        GraphResponse(nodes=result.nodes, edges=result.edges).model_dump(by_alias=True)
    )


@router.get("/query", response_model=QueryResponse)
def query_graph(
    svc: Annotated[GraphQueryService, Depends(get_query_service)],
    start: Optional[str] = Query(default=None, description="Only paths starting from this node name."),
    end: Optional[str] = Query(default=None, description="Only paths ending at this node name."),
    starts_from_public: bool = Query(default=False, description="Paths starting at a publicly exposed node."),
    ends_at_sink: bool = Query(default=False, description="Paths ending at a data sink (rds/sqs)."),
    has_vulnerability: bool = Query(default=False, description="Paths containing at least one vulnerable node."),
    vulnerability_severity: Optional[VulnerabilitySeverity] = Query(default=None, description="Narrow to a specific severity (only applies when has_vulnerability=true)."),
    node_kind: Optional[str] = Query(default=None, description="Paths containing a node of this kind (e.g. 'rds')."),
) -> JSONResponse:
    """
    Return a filtered sub-graph.

    All parameters are optional and freely combinable.
    The response is shaped for direct consumption by graph visualisation libraries.
    """
    filter_params = FilterParams(
        starts_from_public=starts_from_public,
        ends_at_sink=ends_at_sink,
        has_vulnerability=has_vulnerability,
        vulnerability_severity=vulnerability_severity,
        node_kind=node_kind,
    )
    result = svc.query(filters=filter_params.to_filters(), start=start, end=end)
    return JSONResponse(
        QueryResponse(nodes=result.nodes, edges=result.edges, meta=result.meta).model_dump(by_alias=True)
    )
