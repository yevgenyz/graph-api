from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.services.graph_repository import GraphRepository


class Filter(ABC):
    """
    Abstract base for path filters.

    A path is a list of node names [A, B, C, ...].
    `accepts` returns True if the path satisfies this filter's condition.

    Adding a new filter:
      1. Add a typed field to FilterParams.
      2. Subclass Filter and implement `name` and `accepts`.
      3. Add a branch in FilterParams.to_filters().
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def accepts(self, path: list[str], repo: GraphRepository) -> bool: ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"


# ---------------------------------------------------------------------------
# Concrete filters
# ---------------------------------------------------------------------------

class StartsFromPublicFilter(Filter):
    """Accepts paths whose first node is publicly exposed."""

    @property
    def name(self) -> str:
        return "starts_from_public"

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        node = repo.get_node(path[0])
        return node is not None and node.public_exposed


class EndsAtSinkFilter(Filter):
    """Accepts paths whose last node is a data sink (rds/sqs)."""

    @property
    def name(self) -> str:
        return "ends_at_sink"

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        node = repo.get_node(path[-1])
        return node is not None and node.is_sink


class HasVulnerabilityFilter(Filter):
    """
    Accepts paths where at least one node has a vulnerability.
    Optionally scoped to a specific severity level.
    """

    def __init__(self, severity: Optional[VulnerabilitySeverity] = None) -> None:
        if severity is not None and not isinstance(severity, VulnerabilitySeverity):
            raise TypeError(
                f"severity must be a VulnerabilitySeverity enum member, got {type(severity).__name__!r}"
            )
        self._severity = severity

    @property
    def name(self) -> str:
        return (
            f"has_vulnerability[severity={self._severity.value}]"
            if self._severity else "has_vulnerability"
        )

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        for node_name in path:
            node = repo.get_node(node_name)
            if node and node.vulnerabilities:
                if self._severity is None:
                    return True
                if any(v.severity == self._severity for v in node.vulnerabilities):
                    return True
        return False


class NodeKindFilter(Filter):
    """Accepts paths that contain at least one node of the specified kind."""

    def __init__(self, kind: str) -> None:
        self._kind = kind

    @property
    def name(self) -> str:
        return f"node_kind[{self._kind}]"

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        return any(
            (node := repo.get_node(name)) is not None and node.kind == self._kind
            for name in path
        )


# ---------------------------------------------------------------------------
# Typed filter parameters — single source of truth for available filters
# ---------------------------------------------------------------------------

@dataclass
class FilterParams:
    """
    Typed representation of all available query filters.

    This is the single definition that both the route (FastAPI query params)
    and the service (filter instantiation) derive from — eliminating the
    string-key duplication that existed between FILTER_REGISTRY and the
    route function signature.

    `has_vulnerability` and `vulnerability_severity` are intentionally
    separate: the former is the boolean "filter by vulnerability at all",
    the latter optionally narrows it to a specific severity. This keeps
    the enum typed and avoids overloading a single field with two meanings.

    Adding a new filter: add a field here and a branch in `to_filters`.
    """

    starts_from_public: bool = False
    ends_at_sink: bool = False
    has_vulnerability: bool = False
    vulnerability_severity: Optional[VulnerabilitySeverity] = None
    node_kind: Optional[str] = None

    def to_filters(self) -> list[Filter]:
        filters: list[Filter] = []
        if self.starts_from_public:
            filters.append(StartsFromPublicFilter())
        if self.ends_at_sink:
            filters.append(EndsAtSinkFilter())
        if self.has_vulnerability:
            filters.append(HasVulnerabilityFilter(severity=self.vulnerability_severity))
        if self.node_kind is not None:
            filters.append(NodeKindFilter(kind=self.node_kind))
        return filters
