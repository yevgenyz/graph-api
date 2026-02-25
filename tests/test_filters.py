import pytest

from org.xyz.backslash.models.graph import VulnerabilitySeverity
from org.xyz.backslash.services.filters import (
    EndsAtSinkFilter,
    FilterParams,
    HasVulnerabilityFilter,
    NodeKindFilter,
    StartsFromPublicFilter,
    VulnerabilityParams,
)


# ---------------------------------------------------------------------------
# StartsFromPublicFilter
# ---------------------------------------------------------------------------

def test_starts_from_public_accepts_public_node(repo):
    assert StartsFromPublicFilter().accepts(["gateway", "auth-service"], repo) is True


def test_starts_from_public_rejects_private_node(repo):
    assert StartsFromPublicFilter().accepts(["auth-service", "prod-db"], repo) is False


def test_starts_from_public_name():
    assert StartsFromPublicFilter().name == "starts_from_public"


# ---------------------------------------------------------------------------
# EndsAtSinkFilter
# ---------------------------------------------------------------------------

def test_ends_at_sink_accepts_rds(repo):
    assert EndsAtSinkFilter().accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_ends_at_sink_accepts_sqs(repo):
    assert EndsAtSinkFilter().accepts(["gateway", "order-service", "prod-queue"], repo) is True


def test_ends_at_sink_rejects_service_endpoint(repo):
    assert EndsAtSinkFilter().accepts(["gateway", "auth-service"], repo) is False


def test_ends_at_sink_name():
    assert EndsAtSinkFilter().name == "ends_at_sink"


# ---------------------------------------------------------------------------
# HasVulnerabilityFilter
# ---------------------------------------------------------------------------

def test_has_vulnerability_any_accepts_vulnerable_path(repo):
    assert HasVulnerabilityFilter().accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_has_vulnerability_any_rejects_clean_path(repo):
    assert HasVulnerabilityFilter().accepts(["gateway", "prod-db"], repo) is False


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
    assert HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH).name == "has_vulnerability[severity=high]"


def test_has_vulnerability_name_without_severity():
    assert HasVulnerabilityFilter().name == "has_vulnerability"


def test_has_vulnerability_exclude_accepts_clean_path(repo):
    f = HasVulnerabilityFilter(exclude=True)
    assert f.accepts(["gateway", "prod-db"], repo) is True


def test_has_vulnerability_exclude_rejects_vulnerable_path(repo):
    f = HasVulnerabilityFilter(exclude=True)
    assert f.accepts(["gateway", "auth-service", "prod-db"], repo) is False


def test_has_vulnerability_exclude_high_rejects_high_vuln_path(repo):
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH, exclude=True)
    assert f.accepts(["auth-service", "prod-db"], repo) is False


def test_has_vulnerability_exclude_high_accepts_medium_only_path(repo):
    """A path with only medium vulnerabilities should pass an exclude-high filter."""
    f = HasVulnerabilityFilter(severity=VulnerabilitySeverity.HIGH, exclude=True)
    assert f.accepts(["order-service", "prod-db"], repo) is True


def test_has_vulnerability_rejects_raw_string_severity():
    with pytest.raises(TypeError):
        HasVulnerabilityFilter(severity="high")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# NodeKindFilter
# ---------------------------------------------------------------------------

def test_node_kind_matches_rds(repo):
    assert NodeKindFilter("rds").accepts(["gateway", "auth-service", "prod-db"], repo) is True


def test_node_kind_no_match(repo):
    assert NodeKindFilter("rds").accepts(["gateway", "auth-service"], repo) is False


def test_node_kind_name():
    assert NodeKindFilter("rds").name == "node_kind[rds]"


# ---------------------------------------------------------------------------
# VulnerabilityParams
# ---------------------------------------------------------------------------

def test_vulnerability_params_no_severity_produces_any_filter():
    f = VulnerabilityParams().to_filter()
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability"


def test_vulnerability_params_with_severity_produces_scoped_filter():
    f = VulnerabilityParams(severity=VulnerabilitySeverity.HIGH).to_filter()
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability[severity=high]"


def test_vulnerability_params_exclude_produces_negated_filter():
    f = VulnerabilityParams(exclude=True).to_filter()
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "no_vulnerability"


def test_vulnerability_params_exclude_with_severity():
    f = VulnerabilityParams(exclude=True, severity=VulnerabilitySeverity.HIGH).to_filter()
    assert f.name == "no_vulnerability[severity=high]"


# ---------------------------------------------------------------------------
# FilterParams.to_filters()
# ---------------------------------------------------------------------------

def test_filter_params_empty_produces_no_filters():
    assert FilterParams().to_filters() == []


def test_filter_params_start_and_end_do_not_produce_filters():
    """start and end constrain traversal but are not filters — to_filters() ignores them."""
    params = FilterParams(start="gateway", end="prod-db")
    assert params.to_filters() == []
    assert params.start == "gateway"
    assert params.end == "prod-db"


def test_filter_params_starts_from_public():
    filters = FilterParams(starts_from_public=True).to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], StartsFromPublicFilter)


def test_filter_params_ends_at_sink():
    filters = FilterParams(ends_at_sink=True).to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], EndsAtSinkFilter)


def test_filter_params_vulnerability_any():
    filters = FilterParams(vulnerability=VulnerabilityParams()).to_filters()
    assert len(filters) == 1
    f = filters[0]
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability"


def test_filter_params_vulnerability_with_severity():
    filters = FilterParams(
        vulnerability=VulnerabilityParams(severity=VulnerabilitySeverity.HIGH)
    ).to_filters()
    assert len(filters) == 1
    f = filters[0]
    assert isinstance(f, HasVulnerabilityFilter)
    assert f.name == "has_vulnerability[severity=high]"


def test_filter_params_vulnerability_none_means_no_filter():
    """Absence of the vulnerability object means the filter is not applied."""
    filters = FilterParams(vulnerability=None).to_filters()
    assert filters == []


def test_filter_params_node_kind():
    filters = FilterParams(node_kind="rds").to_filters()
    assert len(filters) == 1
    assert isinstance(filters[0], NodeKindFilter)


def test_filter_params_all_combined():
    filters = FilterParams(
        starts_from_public=True,
        ends_at_sink=True,
        vulnerability=VulnerabilityParams(severity=VulnerabilitySeverity.HIGH),
        node_kind="rds",
    ).to_filters()
    assert len(filters) == 4
    types = {type(f) for f in filters}
    assert types == {StartsFromPublicFilter, EndsAtSinkFilter, HasVulnerabilityFilter, NodeKindFilter}
