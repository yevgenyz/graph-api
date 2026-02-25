import pytest
from org.xyz.backslash.services.graph_repository import GraphRepository, JsonFileLoader


def test_node_lookup(repo):
    node = repo.get_node("gateway")
    assert node is not None
    assert node.public_exposed is True


def test_missing_node_returns_none(repo):
    assert repo.get_node("nonexistent") is None


def test_sink_detection_rds(repo):
    assert repo.get_node("prod-db").is_sink is True


def test_sink_detection_sqs(repo):
    assert repo.get_node("prod-queue").is_sink is True


def test_non_sink_service(repo):
    assert repo.get_node("gateway").is_sink is False


def test_vulnerability_detection_positive(repo):
    assert repo.get_node("auth-service").has_vulnerability is True


def test_vulnerability_detection_negative(repo):
    assert repo.get_node("gateway").has_vulnerability is False


def test_all_nodes_count(repo):
    assert len(repo.all_nodes()) == 6


def test_all_edges_count(repo):
    # gateway->auth, gateway->order, auth->prod-db, order->prod-db, order->prod-queue
    assert len(repo.all_edges()) == 5


def test_neighbors(repo):
    assert repo.neighbors("gateway") == {"auth-service", "order-service"}


def test_neighbors_of_sink_is_empty(repo):
    assert repo.neighbors("prod-db") == set()


def test_load_from_file(tmp_path):
    import json
    data_file = tmp_path / "test.json"
    data_file.write_text(json.dumps({
        "nodes": [{"name": "a", "kind": "service"}],
        "edges": [{"from": "a", "to": "b"}],
    }))
    # Should not raise
    repo = GraphRepository(JsonFileLoader(data_file))
    assert repo.get_node("a") is not None


def test_invalid_severity_rejected(tmp_path):
    """Pydantic must reject an unrecognised vulnerability severity."""
    import json
    from pydantic import ValidationError
    data_file = tmp_path / "bad.json"
    data_file.write_text(json.dumps({
        "nodes": [{
            "name": "a", "kind": "service",
            "vulnerabilities": [{"severity": "critical", "message": "oops"}],
        }],
        "edges": [],
    }))
    with pytest.raises(ValidationError):
        GraphRepository(JsonFileLoader(data_file))


def test_missing_required_field_rejected(tmp_path):
    """Pydantic must reject a node missing the required 'kind' field."""
    import json
    from pydantic import ValidationError
    data_file = tmp_path / "bad.json"
    data_file.write_text(json.dumps({
        "nodes": [{"name": "a"}],  # 'kind' is missing
        "edges": [],
    }))
    with pytest.raises(ValidationError):
        GraphRepository(JsonFileLoader(data_file))