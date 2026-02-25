"""
Integration tests verifying the three explicit API requirements via POST /query.
GET /query is covered by a small compatibility class at the bottom.

Dataset facts (train-ticket.json):
  Public nodes:      frontend (has edges), gateway-service (no edges → no paths)
  Sinks:             prod-postgresdb (rds), prod-sqs (sqs)
  Vulnerabilities:   auth-service (medium), order-service (high + medium)
"""

import pytest
from fastapi.testclient import TestClient

from org.xyz.backslash.main import app
from org.xyz.backslash.api.dependencies import get_repository

_REPO = get_repository()

PUBLIC_NODE_NAMES               = {n.name for n in _REPO.all_nodes() if n.public_exposed}
PUBLIC_NODES_WITH_EDGES         = {n.name for n in _REPO.all_nodes() if n.public_exposed and _REPO.neighbors(n.name)}
SINK_NODE_NAMES                 = {n.name for n in _REPO.all_nodes() if n.is_sink}
VULNERABLE_NODE_NAMES           = {n.name for n in _REPO.all_nodes() if n.has_vulnerability}
NODES_WITH_HIGH_VULNERABILITY   = {n.name for n in _REPO.all_nodes() if any(v.severity == "high"   for v in n.vulnerabilities)}
NODES_WITH_MEDIUM_VULNERABILITY = {n.name for n in _REPO.all_nodes() if any(v.severity == "medium" for v in n.vulnerabilities)}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def post_query(client, body: dict) -> dict:
    """POST /query helper."""""
    return client.post("/api/graph/query", json=body).json()


# ---------------------------------------------------------------------------
# Requirement 1: Routes that start in a public service
# ---------------------------------------------------------------------------

class TestStartsFromPublic:
    def test_returns_200(self, client):
        r = client.post("/api/graph/query", json={"starts_from_public": True})
        assert r.status_code == 200

    def test_response_shape(self, client):
        body = post_query(client, {"starts_from_public": True})
        assert "nodes" in body and "edges" in body and "meta" in body

    def test_result_is_non_empty(self, client):
        body = post_query(client, {"starts_from_public": True})
        assert len(body["nodes"]) > 0

    def test_all_path_roots_are_public(self, client):
        body = post_query(client, {"starts_from_public": True})
        edge_targets = {e["to"] for e in body["edges"]}
        root_nodes   = {e["from"] for e in body["edges"]} - edge_targets
        for name in root_nodes:
            assert name in PUBLIC_NODE_NAMES

    def test_public_nodes_with_edges_are_present(self, client):
        body = post_query(client, {"starts_from_public": True})
        node_names = {n["name"] for n in body["nodes"]}
        assert PUBLIC_NODES_WITH_EDGES <= node_names

    def test_public_nodes_without_edges_are_absent(self, client):
        disconnected = PUBLIC_NODE_NAMES - PUBLIC_NODES_WITH_EDGES
        if not disconnected:
            pytest.skip("No disconnected public nodes in this dataset")
        body = post_query(client, {"starts_from_public": True})
        node_names = {n["name"] for n in body["nodes"]}
        for name in disconnected:
            assert name not in node_names

    def test_active_filter_reported_in_meta(self, client):
        body = post_query(client, {"starts_from_public": True})
        assert "starts_from_public" in body["meta"]["active_filters"]


# ---------------------------------------------------------------------------
# Requirement 2: Routes that end in a sink (rds/sqs)
# ---------------------------------------------------------------------------

class TestEndsAtSink:
    def test_returns_200(self, client):
        r = client.post("/api/graph/query", json={"ends_at_sink": True})
        assert r.status_code == 200

    def test_result_is_non_empty(self, client):
        body = post_query(client, {"ends_at_sink": True})
        assert len(body["nodes"]) > 0

    def test_all_sink_nodes_are_present(self, client):
        body = post_query(client, {"ends_at_sink": True})
        node_names = {n["name"] for n in body["nodes"]}
        assert SINK_NODE_NAMES <= node_names

    def test_every_rds_or_sqs_node_is_a_known_sink(self, client):
        body = post_query(client, {"ends_at_sink": True})
        for node in body["nodes"]:
            if node["kind"] in ("rds", "sqs"):
                assert node["name"] in SINK_NODE_NAMES

    def test_active_filter_reported_in_meta(self, client):
        body = post_query(client, {"ends_at_sink": True})
        assert "ends_at_sink" in body["meta"]["active_filters"]


# ---------------------------------------------------------------------------
# Requirement 3: Routes that have a vulnerability in one of the nodes
# ---------------------------------------------------------------------------

class TestHasVulnerability:
    def test_returns_200(self, client):
        r = client.post("/api/graph/query", json={"vulnerability": {}})
        assert r.status_code == 200

    def test_result_is_non_empty(self, client):
        body = post_query(client, {"vulnerability": {}})
        assert len(body["nodes"]) > 0

    def test_all_vulnerable_nodes_are_present(self, client):
        body = post_query(client, {"vulnerability": {}})
        node_names = {n["name"] for n in body["nodes"]}
        assert VULNERABLE_NODE_NAMES <= node_names

    def test_severity_high_includes_all_high_vuln_nodes(self, client):
        body = post_query(client, {"vulnerability": {"severity": "high"}})
        node_names = {n["name"] for n in body["nodes"]}
        assert NODES_WITH_HIGH_VULNERABILITY <= node_names

    def test_severity_medium_includes_all_medium_vuln_nodes(self, client):
        body = post_query(client, {"vulnerability": {"severity": "medium"}})
        node_names = {n["name"] for n in body["nodes"]}
        assert NODES_WITH_MEDIUM_VULNERABILITY <= node_names

    def test_severity_high_result_nodes_carry_high_vuln(self, client):
        body = post_query(client, {"vulnerability": {"severity": "high"}})
        for node in body["nodes"]:
            if node.get("vulnerabilities"):
                severities = {v["severity"] for v in node["vulnerabilities"]}
                assert "high" in severities, (
                    f"'{node['name']}' in high result but vulnerabilities are only: {severities}"
                )

    def test_active_filter_reported_in_meta(self, client):
        body = post_query(client, {"vulnerability": {}})
        assert "has_vulnerability" in body["meta"]["active_filters"]

    def test_invalid_severity_value_returns_422(self, client):
        """An unrecognised severity value must be rejected by Pydantic with a 422."""
        r = client.post("/api/graph/query", json={"vulnerability": {"severity": "critical"}})
        assert r.status_code == 422

    def test_exclude_returns_only_clean_paths(self, client):
        """Paths returned with exclude=true must contain no vulnerable nodes."""
        body = post_query(client, {"vulnerability": {"exclude": True}})
        for node in body["nodes"]:
            assert not node.get("vulnerabilities"), (
                f"Node '{node['name']}' has vulnerabilities but appeared in exclude result"
            )

    def test_exclude_result_does_not_contain_vulnerable_nodes(self, client):
        body = post_query(client, {"vulnerability": {"exclude": True}})
        node_names = {n["name"] for n in body["nodes"]}
        for name in VULNERABLE_NODE_NAMES:
            assert name not in node_names, (
                f"Vulnerable node '{name}' appeared in exclude=true result"
            )


# ---------------------------------------------------------------------------
# Combined filters
# ---------------------------------------------------------------------------

class TestCombinedFilters:
    def test_all_three_combined_returns_200(self, client):
        r = client.post("/api/graph/query", json={
            "starts_from_public": True,
            "ends_at_sink": True,
            "vulnerability": {},
        })
        assert r.status_code == 200

    def test_combined_meta_reports_all_active_filters(self, client):
        body = post_query(client, {
            "starts_from_public": True,
            "ends_at_sink": True,
            "vulnerability": {},
        })
        active = body["meta"]["active_filters"]
        assert "starts_from_public" in active
        assert "ends_at_sink" in active
        assert "has_vulnerability" in active

    def test_public_and_sink_result_is_empty(self, client):
        """No path simultaneously starts at a public node and ends at a sink in this dataset."""
        body = post_query(client, {"starts_from_public": True, "ends_at_sink": True})
        assert body["nodes"] == []
        assert body["edges"] == []
        assert body["meta"]["total_paths"] == 0

