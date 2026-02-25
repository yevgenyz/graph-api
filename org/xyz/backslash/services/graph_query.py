from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from org.xyz.backslash.models.graph import Node
from org.xyz.backslash.models.schemas import EdgeResponse, NodeResponse, QueryMeta, VulnerabilityResponse
from org.xyz.backslash.services.filters import Filter
from org.xyz.backslash.services.graph_repository import GraphRepository


@dataclass
class QueryResult:
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]
    meta: QueryMeta


@dataclass
class GraphResult:
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]


class GraphQueryService:
    """
    Executes path-finding and filtered queries against the graph.

    Uses iterative DFS (explicit stack) rather than recursion to avoid
    Python's default recursion limit, which would become a silent constraint
    on larger graphs.
    """

    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------

    def find_paths(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> list[list[str]]:
        """
        Return all simple (non-repeating) paths in the graph using iterative DFS.

        - start + end  → paths between those two specific nodes
        - start only   → all paths originating from start
        - end only     → all paths terminating at end
        - neither      → all paths from every node (full traversal)
        """
        sources = [start] if start else self._repo.node_names()
        results: list[list[str]] = []
        for src in sources:
            results.extend(self._iter_dfs(src, end))
        return results

    def _iter_dfs(self, start: str, end: Optional[str]) -> list[list[str]]:
        """
        Iterative DFS producing all simple paths from `start`,
        optionally filtered to only those terminating at `end`.

        Each stack frame holds (current_node, path_so_far, visited_set).
        Copying path and visited per frame is the iterative equivalent of
        the implicit backtracking that recursion provides via the call stack.
        """
        results: list[list[str]] = []
        # Stack entries: (current node, path to current node, visited set)
        stack: list[tuple[str, list[str], set[str]]] = [
            (start, [start], {start})
        ]

        while stack:
            current, path, visited = stack.pop()

            if end is None:
                # Collect every prefix longer than a single node
                if len(path) > 1:
                    results.append(path)
            elif current == end:
                results.append(path)
                continue  # don't explore further past the target

            for neighbor in self._repo.neighbors(current):
                if neighbor not in visited:
                    stack.append((
                        neighbor,
                        path + [neighbor],
                        visited | {neighbor},
                    ))

        return results

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------

    def full_graph(self) -> GraphResult:
        """Return all nodes and direct edges."""
        return GraphResult(
            nodes=[self._to_node_response(n) for n in self._repo.all_nodes()],
            edges=[EdgeResponse(source=e.source, target=e.target) for e in self._repo.all_edges()],
        )

    def query(
        self,
        filters: list[Filter],
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> QueryResult:
        """
        Find all paths matching every provided filter and return a typed QueryResult.
        """
        all_paths = self.find_paths(start=start, end=end)

        passing = [
            path for path in all_paths
            if all(f.accepts(path, self._repo) for f in filters)
        ]

        node_names: set[str] = set()
        edge_set: set[tuple[str, str]] = set()
        for path in passing:
            node_names.update(path)
            for i in range(len(path) - 1):
                edge_set.add((path[i], path[i + 1]))

        return QueryResult(
            nodes=[
                self._to_node_response(self._repo.get_node(n))
                for n in node_names
                if self._repo.get_node(n) is not None
            ],
            edges=[EdgeResponse(source=src, target=tgt) for src, tgt in edge_set],
            meta=QueryMeta(
                total_paths=len(passing),
                active_filters=[f.name for f in filters],
            ),
        )

    def get_node_response(self, name: str) -> Optional[NodeResponse]:
        """Return a single node by name, or None if not found."""
        node = self._repo.get_node(name)
        return self._to_node_response(node) if node else None

    # ------------------------------------------------------------------
    # Domain → response model conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _to_node_response(node: Node) -> NodeResponse:
        return NodeResponse(
            name=node.name,
            kind=node.kind,
            language=node.language,
            path=node.path,
            publicExposed=node.public_exposed,
            vulnerabilities=[
                VulnerabilityResponse(
                    file=v.file,
                    severity=v.severity,
                    message=v.message,
                    metadata=v.metadata,
                )
                for v in node.vulnerabilities
            ],
            metadata=node.metadata,
        )
