from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


class NodeKind(str, Enum):
    SERVICE = "service"
    RDS = "rds"
    SQS = "sqs"


class VulnerabilitySeverity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Vulnerability(BaseModel):
    file: Optional[str] = None
    severity: VulnerabilitySeverity
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Node(BaseModel):
    name: str
    kind: str  # kept as str to be forward-compatible with new kinds
    language: Optional[str] = None
    path: Optional[str] = None
    public_exposed: bool = Field(False, alias="publicExposed")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @property
    def is_sink(self) -> bool:
        return self.kind in (NodeKind.RDS, NodeKind.SQS)

    @property
    def has_vulnerability(self) -> bool:
        return len(self.vulnerabilities) > 0

    def vulnerabilities_by_severity(self, severity: VulnerabilitySeverity) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]


class Edge(BaseModel):
    source: str = Field(alias="from")
    target: str = Field(alias="to")

    model_config = {"populate_by_name": True}


class GraphData(BaseModel):
    """
    Parses and validates the raw JSON graph structure.

    The only pre-processing needed before Pydantic takes over is expanding
    edges whose "to" value is a list into individual single-target edges,
    keeping the original "from"/"to" key names that Edge aliases expect.
    """

    nodes: list[Node]
    edges: list[Edge] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def expand_multi_target_edges(cls, data: Any) -> Any:
        expanded = []
        for raw in data.get("edges", []):
            targets = raw["to"] if isinstance(raw["to"], list) else [raw["to"]]
            for tgt in targets:
                expanded.append({"from": raw["from"], "to": tgt})
        data["edges"] = expanded
        return data
