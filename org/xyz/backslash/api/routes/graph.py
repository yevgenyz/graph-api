from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from org.xyz.backslash.api.dependencies import get_query_service
from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.models.schemas import (
    FiltersResponse,
    FilterDoc,
    GraphResponse,
    QueryResponse,
)
from org.xyz.backslash.services.filters import FilterParams
from org.xyz.backslash.services.graph_query import GraphQueryService

router = APIRouter(prefix="/api/graph", tags=["Graph"])

_FILTER_DOCS: dict[str, FilterDoc] = {
    "start": FilterDoc(
        description="Constrain traversal to paths originating from this node.",
        values="any node name",
        example='{"start": "user-service"}',
    ),
    "end": FilterDoc(
        description="Constrain traversal to paths terminating at this node.",
        values="any node name",
        example='{"end": "prod-postgresdb"}',
    ),
    "starts_from_public": FilterDoc(
        description="Include only paths whose first node has publicExposed=true.",
        values="true | false",
        example='{"starts_from_public": true}',
    ),
    "ends_at_sink": FilterDoc(
        description="Include only paths whose last node is a sink (rds/sqs).",
        values="true | false",
        example='{"ends_at_sink": true}',
    ),
    "vulnerability": FilterDoc(
        description="Filter paths by vulnerability. "
                    "By default includes paths containing a vulnerability; "
                    "set 'exclude: true' to include only clean paths. "
                    "Optionally scoped to a specific severity.",
        values="{}  |  {\"severity\": \"" + " | ".join(s.value for s in VulnerabilitySeverity) + "\"}  |  {\"exclude\": true}",
        example='{"vulnerability": {"exclude": true, "severity": "high"}}',
    ),
    "node_kind": FilterDoc(
        description="Include only paths that contain at least one node of the given kind.",
        values="service | rds | sqs | ...",
        example='{"node_kind": "rds"}',
    ),
}


@router.get("/filters", response_model=FiltersResponse, tags=["Filters"])
def list_filters() -> FiltersResponse:
    """Return documentation for all available query parameters."""
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


@router.post("/query", response_model=QueryResponse)
def query_graph(
    svc: Annotated[GraphQueryService, Depends(get_query_service)],
    params: FilterParams,
) -> JSONResponse:
    """
    Return a filtered sub-graph.

    All query inputs are supplied as a JSON body — see FilterParams for the
    full schema. `start` and `end` constrain the traversal scope; all other
    fields filter the resulting paths.

    Note: the response includes all nodes on a matching path, not only the
    nodes that caused the path to match.

    Examples:
        {"start": "user-service", "end": "prod-postgresdb"}
        {"vulnerability": {}}
        {"vulnerability": {"severity": "high"}}
        {"vulnerability": {"exclude": true}}
        {"vulnerability": {"exclude": true, "severity": "high"}}
        {"starts_from_public": true, "ends_at_sink": true, "vulnerability": {"severity": "high"}}
    """
    result = svc.query(filters=params.to_filters(), start=params.start, end=params.end)
    return JSONResponse(
        QueryResponse(nodes=result.nodes, edges=result.edges, meta=result.meta).model_dump(by_alias=True)
    )
