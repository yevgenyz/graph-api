from __future__ import annotations

from pathlib import Path
from typing import Optional

from org.xyz.backslash.core.logging import get_logger
from org.xyz.backslash.models.graph import Edge, GraphData, Node

logger = get_logger(__name__)


class GraphRepository:
    """
    Loads and indexes the graph. Pydantic validates and parses the JSON;
    this class only builds the lookup structures on top of the parsed data.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._adjacency: dict[str, set[str]] = {}

    @classmethod
    def from_file(cls, path: Path) -> "GraphRepository":
        logger.info("Loading graph from %s", path)
        graph_data = GraphData.model_validate_json(path.read_text())
        repo = cls._from_graph_data(graph_data)
        logger.info("Graph loaded: %d nodes, %d edges", len(repo._nodes), len(repo._edges))
        return repo

    @classmethod
    def _from_graph_data(cls, graph_data: GraphData) -> "GraphRepository":
        repo = cls()
        for node in graph_data.nodes:
            repo._nodes[node.name] = node
        for edge in graph_data.edges:
            repo._edges.append(edge)
            repo._adjacency.setdefault(edge.source, set()).add(edge.target)
        return repo

    def get_node(self, name: str) -> Optional[Node]:
        return self._nodes.get(name)

    def all_nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def all_edges(self) -> list[Edge]:
        return list(self._edges)

    def neighbors(self, name: str) -> set[str]:
        return self._adjacency.get(name, set())

    def node_names(self) -> list[str]:
        return list(self._nodes.keys())
