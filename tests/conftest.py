import pytest

from org.xyz.backslash.models.graph import GraphData
from org.xyz.backslash.services.graph_repository import GraphLoader, GraphRepository

FIXTURE_DATA = {
    "nodes": [
        {"name": "gateway",       "kind": "service", "publicExposed": True},
        {"name": "auth-service",  "kind": "service", "publicExposed": False,
         "vulnerabilities": [{"severity": "high", "message": "SQL injection"}]},
        {"name": "order-service", "kind": "service", "publicExposed": False,
         "vulnerabilities": [{"severity": "medium", "message": "Path traversal"}]},
        {"name": "prod-db",       "kind": "rds"},
        {"name": "prod-queue",    "kind": "sqs"},
        {"name": "isolated",      "kind": "service"},
    ],
    "edges": [
        {"from": "gateway",       "to": ["auth-service", "order-service"]},
        {"from": "auth-service",  "to": "prod-db"},
        {"from": "order-service", "to": ["prod-db", "prod-queue"]},
    ],
}


class InMemoryLoader(GraphLoader):
    """Test loader that serves a pre-built GraphData without touching the filesystem."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def load(self) -> GraphData:
        return GraphData.model_validate(self._data)


@pytest.fixture
def repo() -> GraphRepository:
    return GraphRepository(InMemoryLoader(FIXTURE_DATA))