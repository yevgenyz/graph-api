"""
test_requirements.py

Integration tests that verify the three explicit API requirements:

  1. Filter routes that start in a public service (publicExposed: true)
  2. Filter routes that end in a sink (rds/sqs)
  3. Filter routes that have a vulnerability in one of the nodes

Each test hits the real HTTP endpoint against the real data file,
asserting the shape and correctness of the response.

Notes on the dataset (train-ticket.json):
  - Public nodes:     frontend (has edges), gateway-service (NO edges → no paths)
  - Sinks:            prod-postgresdb (rds), prod-sqs (sqs)
  - Vulnerabilities:  auth-service (medium), order-service (high + medium)
"""

import pytest
from fastapi.testclient import TestClient

from org.xyz.backslash.main import app
from org.xyz.backslash.api.dependencies import get_repository

# ---------------------------------------------------------------------------
# Derive expected values directly from the real data — no hardcoding
# ---------------------------------------------------------------------------

_REPO = get_repository()

PUBLIC_NODE_NAMES             = {n.name for n in _REPO.all_nodes() if n.public_exposed}
PUBLIC_NODES_WITH_EDGES       = {n.name for n in _REPO.all_nodes() if n.public_exposed and _REPO.neighbors(n.name)}
SINK_NODE_NAMES               = {n.name for n in _REPO.all_nodes() if n.is_sink}
VULNERABLE_NODE_NAMES         = {n.name for n in _REPO.all_nodes() if n.has_vulnerability}
NODES_WITH_HIGH_VULNERABILITY = {
    n.name for n in _REPO.all_nodes()
    if any(v.severity == "high" for v in n.vulnerabilities)
}
NODES_WITH_MEDIUM_VULNERABILITY = {
    n.name for n in _REPO.all_nodes()
    if any(v.severity == "medium" for v in n.vulnerabilities)
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Requirement 1: Routes that start in a public service
# ---------------------------------------------------------------------------

class TestStartsFromPublic:
    def test_returns_200(self, client):
        r = client.get("/api/graph/query?starts_from_public=true")
        assert r.status_code == 200

    def test_response_has_nodes_and_edges(self, client):
        body = client.get("/api/graph/query?starts_from_public=true").json()
        assert "nodes" in body
        assert "edges" in body

    def test_result_is_non_empty(self, client):
        """There are public nodes with edges in the graph, so paths must exist."""
        body = client.get("/api/graph/query?starts_from_public=true").json()
        assert len(body["nodes"]) > 0

    def test_all_path_roots_are_public(self, client):
        """
        A root node appears as an edge source but never as an edge target.
        Every such root must be a publicly exposed node.
        """
        body = client.get("/api/graph/query?starts_from_public=true").json()
        edge_targets = {e["to"] for e in body["edges"]}
        root_nodes   = {e["from"] for e in body["edges"]} - edge_targets
        for name in root_nodes:
            assert name in PUBLIC_NODE_NAMES, (
                f"'{name}' is a path root but is not publicly exposed"
            )

    def test_public_nodes_with_edges_are_present(self, client):
        """
        Public nodes that have outgoing edges must appear in the result.
        Public nodes with no outgoing edges (e.g. gateway-service) produce
        no paths and are correctly absent.
        """
        body = client.get("/api/graph/query?starts_from_public=true").json()
        node_names = {n["name"] for n in body["nodes"]}
        assert PUBLIC_NODES_WITH_EDGES <= node_names, (
            f"Expected {PUBLIC_NODES_WITH_EDGES} to be present, got {node_names}"
        )

    def test_public_nodes_without_edges_are_absent(self, client):
        """
        gateway-service is public but has no outgoing edges, so it must not
        appear — there is no path starting from it.
        """
        disconnected = PUBLIC_NODE_NAMES - PUBLIC_NODES_WITH_EDGES
        if not disconnected:
            pytest.skip("No disconnected public nodes in this dataset")
        body = client.get("/api/graph/query?starts_from_public=true").json()
        node_names = {n["name"] for n in body["nodes"]}
        for name in disconnected:
            assert name not in node_names, (
                f"'{name}' is public with no edges but appeared in path results"
            )

    def test_active_filter_reported_in_meta(self, client):
        body = client.get("/api/graph/query?starts_from_public=true").json()
        assert "starts_from_public" in body["meta"]["active_filters"]


# ---------------------------------------------------------------------------
# Requirement 2: Routes that end in a sink (rds/sqs)
# ---------------------------------------------------------------------------

class TestEndsAtSink:
    def test_returns_200(self, client):
        r = client.get("/api/graph/query?ends_at_sink=true")
        assert r.status_code == 200

    def test_result_is_non_empty(self, client):
        body = client.get("/api/graph/query?ends_at_sink=true").json()
        assert len(body["nodes"]) > 0

    def test_all_sink_nodes_are_present(self, client):
        """Both prod-postgresdb (rds) and prod-sqs (sqs) must appear."""
        body = client.get("/api/graph/query?ends_at_sink=true").json()
        node_names = {n["name"] for n in body["nodes"]}
        assert SINK_NODE_NAMES <= node_names, (
            f"Expected sink nodes {SINK_NODE_NAMES} to be present, got {node_names}"
        )

    def test_every_rds_or_sqs_node_is_a_known_sink(self, client):
        """Every node with kind rds or sqs must be among the known sinks."""
        body = client.get("/api/graph/query?ends_at_sink=true").json()
        for node in body["nodes"]:
            if node["kind"] in ("rds", "sqs"):
                assert node["name"] in SINK_NODE_NAMES

    def test_active_filter_reported_in_meta(self, client):
        body = client.get("/api/graph/query?ends_at_sink=true").json()
        assert "ends_at_sink" in body["meta"]["active_filters"]


# ---------------------------------------------------------------------------
# Requirement 3: Routes that have a vulnerability in one of the nodes
# ---------------------------------------------------------------------------

class TestHasVulnerability:
    def test_returns_200(self, client):
        r = client.get("/api/graph/query?has_vulnerability=true")
        assert r.status_code == 200

    def test_result_is_non_empty(self, client):
        body = client.get("/api/graph/query?has_vulnerability=true").json()
        assert len(body["nodes"]) > 0

    def test_all_vulnerable_nodes_are_present(self, client):
        """Both auth-service and order-service must appear in the result."""
        body = client.get("/api/graph/query?has_vulnerability=true").json()
        node_names = {n["name"] for n in body["nodes"]}
        assert VULNERABLE_NODE_NAMES <= node_names, (
            f"Expected {VULNERABLE_NODE_NAMES} to be present, got {node_names}"
        )

    def test_severity_high_includes_all_high_vuln_nodes(self, client):
        """order-service is the only high-severity node in the dataset."""
        body = client.get("/api/graph/query?has_vulnerability=true&vulnerability_severity=high").json()
        node_names = {n["name"] for n in body["nodes"]}
        assert NODES_WITH_HIGH_VULNERABILITY <= node_names, (
            f"Expected {NODES_WITH_HIGH_VULNERABILITY} in high result, got {node_names}"
        )

    def test_severity_medium_includes_all_medium_vuln_nodes(self, client):
        """auth-service and order-service both carry medium-severity vulnerabilities."""
        body = client.get("/api/graph/query?has_vulnerability=true&vulnerability_severity=medium").json()
        node_names = {n["name"] for n in body["nodes"]}
        assert NODES_WITH_MEDIUM_VULNERABILITY <= node_names, (
            f"Expected {NODES_WITH_MEDIUM_VULNERABILITY} in medium result, got {node_names}"
        )

    def test_severity_high_result_contains_only_paths_with_high_vuln(self, client):
        """
        Every node that has vulnerabilities listed in a high-severity result
        must carry at least one high-severity vulnerability.
        """
        body = client.get("/api/graph/query?has_vulnerability=true&vulnerability_severity=high").json()
        for node in body["nodes"]:
            if node.get("vulnerabilities"):
                severities = {v["severity"] for v in node["vulnerabilities"]}
                assert "high" in severities, (
                    f"Node '{node['name']}' appears in high result "
                    f"but its vulnerabilities are only: {severities}"
                )

    def test_active_filter_reported_in_meta(self, client):
        body = client.get("/api/graph/query?has_vulnerability=true").json()
        assert "has_vulnerability" in body["meta"]["active_filters"]


# ---------------------------------------------------------------------------
# Requirement: all three filters are combinable
# ---------------------------------------------------------------------------

class TestCombinedFilters:
    def test_public_and_sink_returns_200(self, client):
        r = client.get("/api/graph/query?starts_from_public=true&ends_at_sink=true")
        assert r.status_code == 200

    def test_all_three_combined_returns_200(self, client):
        r = client.get(
            "/api/graph/query"
            "?starts_from_public=true&ends_at_sink=true&has_vulnerability=true"
        )
        assert r.status_code == 200

    def test_combined_meta_reports_all_active_filters(self, client):
        body = client.get(
            "/api/graph/query"
            "?starts_from_public=true&ends_at_sink=true&has_vulnerability=true"
        ).json()
        active = body["meta"]["active_filters"]
        assert "starts_from_public" in active
        assert "ends_at_sink" in active
        assert "has_vulnerability" in active

    def test_public_and_sink_result_is_empty(self, client):
        """
        In this dataset, no path simultaneously starts at a public node and
        ends at a sink. frontend (the only public node with edges) connects
        to admin-basic-info-service, whose subtree has no path to prod-postgresdb
        or prod-sqs. The combined filter must therefore return an empty result.
        """
        body = client.get(
            "/api/graph/query?starts_from_public=true&ends_at_sink=true"
        ).json()
        assert body["nodes"] == [], "Expected no nodes for public+sink combination"
        assert body["edges"] == [], "Expected no edges for public+sink combination"
        assert body["meta"]["total_paths"] == 0
