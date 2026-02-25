import pytest

from org.xyz.backslash.models.graph import GraphData
from org.xyz.backslash.services.graph_repository import GraphRepository

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


@pytest.fixture
def repo() -> GraphRepository:
    return GraphRepository._from_graph_data(GraphData.model_validate(FIXTURE_DATA))
