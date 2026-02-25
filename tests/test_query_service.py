import pytest
from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.services.filters import (
    EndsAtSinkFilter,
    HasVulnerabilityFilter,
    StartsFromPublicFilter,
)
from org.xyz.backslash.services.graph_query import GraphQueryService


@pytest.fixture
def svc(repo):
    return GraphQueryService(repo)


# ---------------------------------------------------------------------------
# Path finding
# ---------------------------------------------------------------------------

def test_find_paths_between_two_nodes(svc):
    paths = svc.find_paths("gateway", "prod-db")
    assert len(paths) == 2
    assert all(p[0] == "gateway" and p[-1] == "prod-db" for p in paths)


def test_find_paths_from_start(svc):
    paths = svc.find_paths(start="gateway")
    assert all(p[0] == "gateway" for p in paths)
    assert len(paths) > 0


def test_find_paths_to_end(svc):
    paths = svc.find_paths(end="prod-db")
    assert all(p[-1] == "prod-db" for p in paths)


def test_find_paths_full_traversal_has_multi_hop(svc):
    paths = svc.find_paths()
    assert any(len(p) > 2 for p in paths)


def test_find_paths_isolated_node_has_no_paths(svc):
    paths = svc.find_paths(start="isolated")
    assert paths == []


def test_no_cycles_in_paths(svc):
    for path in svc.find_paths():
        assert len(path) == len(set(path)), f"Cycle detected in path: {path}"


# ---------------------------------------------------------------------------
# full_graph
# ---------------------------------------------------------------------------

def test_full_graph_returns_all_nodes(svc):
    result = svc.full_graph()
    assert len(result.nodes) == 6


def test_full_graph_returns_all_edges(svc):
    result = svc.full_graph()
    assert len(result.edges) == 5


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

def test_query_no_filters_returns_nodes_and_edges(svc):
    result = svc.query(filters=[])
    assert len(result.nodes) > 0
    assert len(result.edges) > 0
    assert result.meta.total_paths > 0


def test_query_starts_from_public(svc):
    result = svc.query(filters=[StartsFromPublicFilter()])
    node_names = {n.name for n in result.nodes}
    assert "gateway" in node_names


def test_query_ends_at_sink(svc):
    result = svc.query(filters=[EndsAtSinkFilter()])
    node_names = {n.name for n in result.nodes}
    assert "prod-db" in node_names or "prod-queue" in node_names


def test_query_has_vulnerability_high(svc):
    result = svc.query(filters=[HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH)])
    node_names = {n.name for n in result.nodes}
    assert "auth-service" in node_names


def test_query_combined_public_and_sink(svc):
    result = svc.query(filters=[StartsFromPublicFilter(), EndsAtSinkFilter()])
    node_names = {n.name for n in result.nodes}
    assert "gateway" in node_names
    assert len(result.edges) > 0


def test_query_meta_tracks_active_filters(svc):
    result = svc.query(filters=[StartsFromPublicFilter(), EndsAtSinkFilter()])
    assert "starts_from_public" in result.meta.active_filters
    assert "ends_at_sink" in result.meta.active_filters


def test_query_with_start_constrains_paths(svc):
    result = svc.query(filters=[], start="auth-service")
    node_names = {n.name for n in result.nodes}
    assert "auth-service" in node_names
    assert "gateway" not in node_names


def test_query_empty_result_for_unreachable_combination(svc):
    result = svc.query(filters=[EndsAtSinkFilter()], start="isolated")
    assert result.edges == []
    assert result.nodes == []


# ---------------------------------------------------------------------------
# get_node_response
# ---------------------------------------------------------------------------

def test_get_node_response_returns_node(svc):
    node = svc.get_node_response("gateway")
    assert node is not None
    assert node.name == "gateway"
    assert node.publicExposed is True


def test_get_node_response_returns_none_for_missing(svc):
    assert svc.get_node_response("nonexistent") is None
