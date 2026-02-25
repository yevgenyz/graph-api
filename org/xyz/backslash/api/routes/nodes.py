from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from org.xyz.backslash.api.dependencies import get_query_service
from org.xyz.backslash.models.schemas import NodeListResponse, NodeResponse
from org.xyz.backslash.services.graph_query import GraphQueryService

router = APIRouter(prefix="/api/nodes", tags=["Nodes"])


@router.get("", response_model=NodeListResponse)
def list_nodes(
    svc: Annotated[GraphQueryService, Depends(get_query_service)],
) -> NodeListResponse:
    """Return all nodes in the graph."""
    result = svc.full_graph()
    return NodeListResponse(nodes=result.nodes, count=len(result.nodes))


@router.get("/{name}", response_model=NodeResponse)
def get_node(
    name: str,
    svc: Annotated[GraphQueryService, Depends(get_query_service)],
) -> NodeResponse:
    """Return a single node by name."""
    node = svc.get_node_response(name)
    if node is None:
        raise HTTPException(status_code=404, detail=f"Node '{name}' not found.")
    return node
