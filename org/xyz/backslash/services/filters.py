from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel

from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.services.graph_repository import GraphRepository


class Filter(ABC):
    """
    Abstract base for path filters.

    A path is a list of node names [A, B, C, ...].
    `accepts` returns True if the path satisfies this filter's condition.

    Adding a new filter:
      1. Subclass Filter and implement `accepts`.
      2. Add a typed field to FilterParams.
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
    Filters paths by presence or absence of vulnerabilities.

    exclude=False (default): accepts paths where at least one node has a vulnerability.
    exclude=True:            accepts paths where no node has a vulnerability.

    Both modes optionally scope to a specific severity level.
    """

    def __init__(
        self,
        severity: Optional[VulnerabilitySeverity] = None,
        exclude: bool = False,
    ) -> None:
        if severity is not None and not isinstance(severity, VulnerabilitySeverity):
            raise TypeError(
                f"severity must be a VulnerabilitySeverity enum member, got {type(severity).__name__!r}"
            )
        self._severity = severity
        self._exclude = exclude

    @property
    def name(self) -> str:
        base = "no_vulnerability" if self._exclude else "has_vulnerability"
        if self._severity:
            return f"{base}[severity={self._severity.value}]"
        return base

    def _node_matches(self, path: list[str], repo: GraphRepository) -> bool:
        """Return True if any node on the path has a matching vulnerability."""
        for node_name in path:
            node = repo.get_node(node_name)
            if node and node.vulnerabilities:
                if self._severity is None:
                    return True
                if any(v.severity == self._severity for v in node.vulnerabilities):
                    return True
        return False

    def accepts(self, path: list[str], repo: GraphRepository) -> bool:
        matched = self._node_matches(path, repo)
        return not matched if self._exclude else matched


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

class VulnerabilityParams(BaseModel):
    """
    Groups vulnerability filter options into a single coherent object.

    Presence of this object means "filter by vulnerability". The optional
    fields narrow the filter:

      {}                              → paths containing any vulnerability
      {"severity": "high"}           → paths containing a high-severity vulnerability
      {"exclude": true}              → paths containing NO vulnerabilities
      {"exclude": true, "severity": "high"} → paths containing no high-severity vulnerability
    """
    severity: Optional[VulnerabilitySeverity] = None
    exclude: bool = False

    def to_filter(self) -> HasVulnerabilityFilter:
        return HasVulnerabilityFilter(severity=self.severity, exclude=self.exclude)


class FilterParams(BaseModel):
    """
    Pydantic model representing a complete graph query.

    Used as a POST request body, giving us Pydantic validation, clear
    OpenAPI schema generation, and a single place to define query inputs.

    `start` and `end` constrain the traversal to a specific source/destination
    node. All other fields are filters applied to the resulting paths.

    `vulnerability` is an optional nested object — its presence means "apply
    the vulnerability filter", its absence means "don't", with no incoherent
    intermediate state.

    Adding a new filter: add a typed field here and a branch in to_filters().
    """

    start: Optional[str] = None
    end: Optional[str] = None
    starts_from_public: bool = False
    ends_at_sink: bool = False
    vulnerability: Optional[VulnerabilityParams] = None
    node_kind: Optional[str] = None

    def to_filters(self) -> list[Filter]:
        filters: list[Filter] = []
        if self.starts_from_public:
            filters.append(StartsFromPublicFilter())
        if self.ends_at_sink:
            filters.append(EndsAtSinkFilter())
        if self.vulnerability is not None:
            filters.append(self.vulnerability.to_filter())
        if self.node_kind is not None:
            filters.append(NodeKindFilter(kind=self.node_kind))
        return filters
