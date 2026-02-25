from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from org.xyz.backslash.core.logging import get_logger
from org.xyz.backslash.models.graph import Edge, GraphData, Node

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Loader abstraction
# ---------------------------------------------------------------------------

class GraphLoader(ABC):
    """
    Abstract source of graph data.

    Implementations are responsible for fetching and parsing data from a
    specific source and format into the canonical GraphData domain model.
    Adding a new source or format means adding a new GraphLoader subclass —
    GraphRepository and everything above it are unaffected.
    """

    @abstractmethod
    def load(self) -> GraphData: ...


class JsonFileLoader(GraphLoader):
    """Loads graph data from a local JSON file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> GraphData:
        logger.info("Loading graph from %s", self._path)
        return GraphData.model_validate_json(self._path.read_text())


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class GraphRepository:
    """
    Indexes graph data for efficient querying.

    Accepts any GraphLoader — the source and format of the data are not
    its concern. Builds O(1) node lookup and an adjacency map on top of
    the parsed GraphData.
    """

    def __init__(self, loader: GraphLoader) -> None:
        graph_data = loader.load()
        self._nodes: dict[str, Node] = {n.name: n for n in graph_data.nodes}
        self._edges: list[Edge] = list(graph_data.edges)
        self._adjacency: dict[str, set[str]] = {}
        for edge in self._edges:
            self._adjacency.setdefault(edge.source, set()).add(edge.target)
        logger.info("Graph loaded: %d nodes, %d edges", len(self._nodes), len(self._edges))

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
