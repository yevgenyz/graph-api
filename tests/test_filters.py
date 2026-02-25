import pytest
from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.services.filters import (
    EndsAtSinkFilter,
    FilterParams,
    HasVulnerabilityFilter,
    NodeKindFilter,
    StartsFromPublicFilter,
)


# ---------------------------------------------------------------------------
# StartsFromPublicFilter
# ---------------------------------------------------------------------------

def test_starts_from_public_accepts_public_node(repo):
    f = StartsFromPublicFilter()
    assert f.accepts(["gateway", "auth-service"], repo) is True


def test_starts_from_public_rejects_private_node(repo):
    f = StartsFromPublicFilter()
    assert f.accepts(["auth-service", "prod-db"], repo) is False


def test_starts_from_public_name():
    assert StartsFromPublicFilter().name == "starts_from_public"


# ---------------------------------------------------------------------------
# EndsAtSinkFilter
# ---------------------------------------------------------------------------

def test_ends_at_sink_accepts_rds(repo):
    f = EndsAtSinkFilter()
    assert f.accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_ends_at_sink_accepts_sqs(repo):
    f = EndsAtSinkFilter()
    assert f.accepts(["gateway", "order-service", "prod-queue"], repo) is True


def test_ends_at_sink_rejects_service_endpoint(repo):
    f = EndsAtSinkFilter()
    assert f.accepts(["gateway", "auth-service"], repo) is False


def test_ends_at_sink_name():
    assert EndsAtSinkFilter().name == "ends_at_sink"


# ---------------------------------------------------------------------------
# HasVulnerabilityFilter
# ---------------------------------------------------------------------------

def test_has_vulnerability_any_accepts_vulnerable_path(repo):
    f = HasVulnerabilityFilter()
    assert f.accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_has_vulnerability_any_rejects_clean_path(repo):
    f = HasVulnerabilityFilter()
    assert f.accepts(["gateway", "prod-db"], repo) is False


def test_has_vulnerability_high_matches(repo):
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH)
    assert f.accepts(["auth-service", "prod-db"], repo) is True


def test_has_vulnerability_high_no_match(repo):
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH)
    assert f.accepts(["order-service", "prod-db"], repo) is False


def test_has_vulnerability_medium_matches(repo):
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.MEDIUM)
    assert f.accepts(["order-service", "prod-db"], repo) is True


def test_has_vulnerability_name_with_severity():
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH)
    assert f.name == "has_vulnerability[severity=high]"


def test_has_vulnerability_name_without_severity():
    assert HasVulnerabilityFilter().name == "has_vulnerability"


# ---------------------------------------------------------------------------
# NodeKindFilter
# ---------------------------------------------------------------------------

def test_node_kind_matches_rds(repo):
    f = NodeKindFilter("rds")
    assert f.accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_node_kind_no_match(repo):
    f = NodeKindFilter("rds")
    assert f.accepts(["gateway", "auth-service"], repo) is False


def test_node_kind_name():
    assert NodeKindFilter("rds").name == "node_kind[rds]"


# ---------------------------------------------------------------------------
# FilterParams.to_filters()
# ---------------------------------------------------------------------------

def test_filter_params_all_disabled_produces_no_filters():
    assert FilterParams().to_filters() == []


def test_filter_params_starts_from_public():
    filters = FilterParams(starts_from_public=True).to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], StartsFromPublicFilter)


def test_filter_params_ends_at_sink():
    filters = FilterParams(ends_at_sink=True).to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], EndsAtSinkFilter)


def test_filter_params_has_vulnerability_any():
    filters = FilterParams(has_vulnerability=True).to_filters()
    assert len(filters) == 1
    f = filters[0]
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability"


def test_filter_params_has_vulnerability_with_severity():
    filters = FilterParams(
        has_vulnerability=True,
        vulnerability_severity=VulnerabilitySeverity.HIGH,
    ).to_filters()
    assert len(filters) == 1
    f = filters[0]
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability[severity=high]"


def test_filter_params_vulnerability_severity_ignored_without_flag():
    """vulnerability_severity has no effect if has_vulnerability is False."""
    filters = FilterParams(
        has_vulnerability=False,
        vulnerability_severity=VulnerabilitySeverity.HIGH,
    ).to_filters()
    assert filters == []


def test_filter_params_node_kind():
    filters = FilterParams(node_kind="rds").to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], NodeKindFilter)


def test_filter_params_all_combined():
    filters = FilterParams(
        starts_from_public=True,
        ends_at_sink=True,
        has_vulnerability=True,
        vulnerability_severity=VulnerabilitySeverity.HIGH,
        node_kind="rds",
    ).to_filters()
    assert len(filters) == 4
    types = [type(f) for f in filters]
    assert StartsFromPublicFilter in types
    assert EndsAtSinkFilter in types
    assert HasVulnerabilityFilter in types
    assert NodeKindFilter in types
