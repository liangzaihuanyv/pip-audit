from __future__ import annotations

import json
import socket

import pretend  # type: ignore
import pytest
from packaging.version import InvalidVersion, Version
from requests.exceptions import ConnectTimeout, HTTPError

import pip_audit._service as service
from pip_audit._audit import Auditor
from pip_audit._dependency_source import DependencySource
from pip_audit._fix import ResolvedFixVersion, resolve_fix_versions


def get_mock_session(func):
    class MockSession:
        def __init__(self, create_response):
            self.create_response = create_response

        def post(self, url, **kwargs):
            return self.create_response()

    return MockSession(func)


@pytest.mark.online
def test_osv():
    osv = service.OsvService()
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_osv_uses_canonical_package_name():
    # OSV's API only recognizes canonicalized package names, so make sure
    # that our adapter is canonicalizing any dependencies passed into it.
    osv = service.OsvService()
    dep = service.ResolvedDependency("PyYAML", Version("5.3"))
    _, results = osv.query(dep)

    assert len(results) > 0


@pytest.mark.online
def test_osv_version_ranges():
    # Try a package with vulnerabilities that have an explicitly stated introduced and fixed
    # version
    osv = service.OsvService()
    dep = service.ResolvedDependency("ansible", Version("2.8.0"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_osv_multiple_pkg():
    osv = service.OsvService()
    deps: list[service.Dependency] = [
        service.ResolvedDependency("jinja2", Version("2.4.1")),
        service.ResolvedDependency("flask", Version("0.5")),
    ]
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        osv.query_all(iter(deps))
    )

    assert len(results) == 2
    assert deps[0] in results and deps[1] in results

    assert len(results[deps[0]]) > 0
    assert len(results[deps[1]]) > 0


@pytest.mark.online
def test_osv_no_vuln():
    osv = service.OsvService()
    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


def test_osv_connection_error(monkeypatch):
    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", pretend.raiser(ConnectTimeout))

    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(
        service.ConnectionError, match="Could not connect to OSV's vulnerability feed"
    ):
        dict(osv.query_all(iter([dep])))


def test_osv_error_response(monkeypatch):
    def raise_for_status():
        raise HTTPError

    response = pretend.stub(raise_for_status=pretend.call_recorder(raise_for_status))
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(service.ServiceError):
        dict(osv.query_all(iter([dep])))

    assert len(post.calls) == 1
    assert len(response.raise_for_status.calls) == 1


def test_osv_skipped_dep():
    osv = service.OsvService()
    dep = service.SkippedDependency(name="foo", skip_reason="skip-reason")
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.parametrize("version", ["0.0.0", "2.0.0", "2.3.4"])
def test_osv_unsupported_schema_version(monkeypatch, version):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.osv, "logger", logger)

    payload = {
        "vulns": [
            {"schema_version": version},
        ]
    }

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(osv.query_all(iter([dep])))

    assert logger.warning.calls == [pretend.call(f"Unsupported OSV schema version: {version}")]

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.parametrize(
    ["summary", "details", "description"],
    [
        ("fakesummary", "fakedetails", "fakesummary"),
        ("fakesummary\nanother line", "fakedetails", "fakesummary another line"),
        (None, "fakedetails", "fakedetails"),
        (None, "fakedetails\nanother line", "fakedetails another line"),
        (None, None, "N/A"),
    ],
)
def test_osv_vuln_description_fallbacks(monkeypatch, summary, details, description):
    payload = {
        "vulns": [
            {
                "id": "fakeid",
                "summary": summary,
                "details": details,
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0.1"}]}],
                    }
                ],
            }
        ],
    }

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(osv.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 1

    assert vulns[0].description == description


def test_osv_vuln_affected_missing(monkeypatch):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.osv, "logger", logger)

    payload = {
        "vulns": [
            {
                "id": "fakeid",
                "summary": "fakesummary",
                "details": "fakedetails",
            }
        ],
    }

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(osv.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0

    assert logger.warning.calls == [
        pretend.call("OSV vuln entry 'fakeid' is missing 'affected' list")
    ]


def test_osv_vuln_ranges_missing(monkeypatch):
    # An affected entry with no 'ranges' key is valid per the OSV schema
    # (ranges is optional); pip-audit should not crash with a KeyError.
    payload = {
        "vulns": [
            {
                "id": "fakeid",
                "summary": "fakesummary",
                "details": "fakedetails",
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": "PyPI"},
                        "versions": ["1.0.0"],
                    }
                ],
            }
        ],
    }

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(osv.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    # No fix versions available without ranges, so the vuln is still reported
    # but with an empty fix_versions list (no KeyError raised).
    vulns = results[dep]
    assert len(vulns) == 1
    assert vulns[0].fix_versions == []


def test_osv_vuln_withdrawn(monkeypatch):
    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.osv, "logger", logger)

    payload = {
        "vulns": [
            {
                "id": "fakeid",
                "withdrawn": "some-datetime",
            }
        ],
    }

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(osv.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0

    assert logger.debug.calls == [
        pretend.call("OSV vuln entry 'fakeid' marked as withdrawn at some-datetime")
    ]


# The payloads below are synthetic but schema-valid OSV v1.0.0 records. No live
# advisory is claimed to have these exact shapes; they pin down the schema rule that
# a version is affected if it lies within any one of the affected ranges, including
# when the same package is named by more than one `affected` entry.


def _osv_range(range_type: str, *fixed_versions: str, introduced: str = "0") -> dict:
    events = [{"introduced": introduced}]
    events.extend({"fixed": version} for version in fixed_versions)
    osv_range = {"type": range_type, "events": events}
    if range_type == "GIT":
        osv_range["repo"] = "https://example.invalid/demo-pkg.git"
    return osv_range


def _osv_affected(name: str, ecosystem: str, *ranges: dict) -> dict:
    return {
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": list(ranges),
    }


def _osv_payload(*affected: dict) -> dict:
    return {
        "vulns": [
            {
                "id": "PYSEC-2026-9",
                "schema_version": "1.0.0",
                "modified": "2026-01-01T00:00:00Z",
                "summary": "Synthetic multi-range advisory used by pip-audit's test suite",
                "affected": list(affected),
            }
        ]
    }


def _osv_with_payload(monkeypatch, payload: dict):
    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    post = pretend.call_recorder(lambda *args, **kwargs: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    return osv, post


_RANGE_LAYOUTS = {
    "single-affected": lambda ranges: [_osv_affected("demo-pkg", "PyPI", *ranges)],
    "two-affected": lambda ranges: [_osv_affected("demo-pkg", "PyPI", r) for r in ranges],
}


@pytest.mark.parametrize("layout", sorted(_RANGE_LAYOUTS))
@pytest.mark.parametrize("order", ["forward", "reversed"])
def test_osv_multiple_ecosystem_ranges(monkeypatch, layout, order):
    # Multiple non-overlapping ECOSYSTEM ranges for the same package are legal, and
    # every `fixed` event in every range is a fix version -- not just the first.
    ranges = [
        _osv_range("ECOSYSTEM", "0.9.0"),
        _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
    ]
    if order == "reversed":
        ranges.reverse()

    payload = _osv_payload(*_RANGE_LAYOUTS[layout](ranges))
    osv, post = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    _, results = osv.query(dep)

    assert len(post.calls) == 1
    assert len(results) == 1
    assert results[0].fix_versions == [Version("0.9.0"), Version("1.2.0")]


def test_osv_multiple_affected_entries_retain_earlier_fix(monkeypatch):
    # A later matching affected entry must add to the earlier entry's fixes rather
    # than overwrite them (the first entry's 0.9.0 was previously lost).
    payload = _osv_payload(
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "0.9.0")),
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0")),
    )
    osv, _ = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    _, results = osv.query(dep)

    assert len(results) == 1
    assert results[0].fix_versions == [Version("0.9.0"), Version("1.2.0")]


_DUPLICATE_LAYOUTS = {
    "across-affected-entries": lambda: [
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "0.9.0")),
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "0.9.0")),
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0")),
    ],
    "repeated-fix-in-separate-ranges": lambda: [
        _osv_affected(
            "demo-pkg",
            "PyPI",
            _osv_range("ECOSYSTEM", "0.9.0"),
            _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
        ),
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "0.9.0")),
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0")),
    ],
}


@pytest.mark.parametrize("layout", sorted(_DUPLICATE_LAYOUTS))
def test_osv_duplicate_fix_versions_deduplicated(monkeypatch, layout):
    # A fix version repeated across affected entries (legal per the schema) must be
    # reported once, in sorted order. Each range is a valid non-overlapping interval.
    payload = _osv_payload(*_DUPLICATE_LAYOUTS[layout]())
    osv, _ = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    _, results = osv.query(dep)

    assert len(results) == 1
    assert results[0].fix_versions == [Version("0.9.0"), Version("1.2.0")]


def test_osv_mixed_unrelated_entries_ignored(monkeypatch):
    # Only ECOSYSTEM ranges belonging to the queried canonical PyPI package count.
    payload = _osv_payload(
        _osv_affected("demo-pkg", "npm", _osv_range("ECOSYSTEM", "9.9.9")),
        _osv_affected("other-pkg", "PyPI", _osv_range("ECOSYSTEM", "8.8.8")),
        _osv_affected("demo-pkg", "PyPI", _osv_range("GIT", "a" * 40)),
        _osv_affected("demo-pkg", "PyPI", _osv_range("SEMVER", "7.7.7")),
        _osv_affected(
            "demo-pkg",
            "PyPI",
            _osv_range("ECOSYSTEM", "0.9.0"),
            _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
        ),
    )
    osv, _ = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    _, results = osv.query(dep)

    assert len(results) == 1
    assert results[0].fix_versions == [Version("0.9.0"), Version("1.2.0")]


def test_osv_absent_ranges_alongside_matching_entry(monkeypatch):
    # `ranges` stays optional per affected entry: an entry without it contributes no
    # fix versions but must not discard fixes gathered from other entries.
    payload = _osv_payload(
        {"package": {"name": "demo-pkg", "ecosystem": "PyPI"}, "versions": ["1.0.0"]},
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.2.0")),
    )
    osv, _ = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    _, results = osv.query(dep)

    assert len(results) == 1
    assert results[0].fix_versions == [Version("1.2.0")]


def test_osv_invalid_fixed_version_still_raises(monkeypatch):
    # Existing behaviour is preserved: an unparsable `fixed` value propagates
    # `InvalidVersion` out of `query()`.
    payload = _osv_payload(
        _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "not-a-version")),
    )
    osv, _ = _osv_with_payload(monkeypatch, payload)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    with pytest.raises(InvalidVersion):
        osv.query(dep)


def _assert_event_semantics(payload: dict) -> None:
    for vuln in payload["vulns"]:
        for affected in vuln["affected"]:
            for osv_range in affected.get("ranges", []):
                events = osv_range["events"]
                assert "introduced" in events[0], "range must start with introduced"
                introduced = None
                intervals = []
                for event in events:
                    if "introduced" in event:
                        assert introduced is None, "consecutive introduced events"
                        introduced = event["introduced"]
                    else:
                        assert introduced is not None, "fixed event before introduced"
                        intervals.append((introduced, event["fixed"]))
                        introduced = None
                if osv_range["type"] == "ECOSYSTEM":
                    parsed = [(Version(start), Version(end)) for start, end in intervals]
                    for start, end in parsed:
                        assert start < end, "empty or reversed range"
                    for (_, end), (start, _) in zip(parsed, parsed[1:]):
                        assert end <= start, "overlapping ECOSYSTEM ranges"


def test_osv_synthetic_fixtures_are_semantically_valid():
    # JSON-schema validity is checked against the official OSV schema in the
    # offline artifact; the schema does not encode event ordering, so pin the
    # semantics our fixtures rely on: non-overlapping ECOSYSTEM intervals with
    # exactly one introduced event before each fixed event.
    payloads = [
        _osv_payload(
            *_RANGE_LAYOUTS[layout](
                [
                    _osv_range("ECOSYSTEM", "0.9.0"),
                    _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
                ]
            )
        )
        for layout in sorted(_RANGE_LAYOUTS)
    ]
    payloads += [
        _osv_payload(*_DUPLICATE_LAYOUTS[layout]()) for layout in sorted(_DUPLICATE_LAYOUTS)
    ]
    payloads.append(
        _osv_payload(
            _osv_affected("demo-pkg", "npm", _osv_range("ECOSYSTEM", "9.9.9")),
            _osv_affected("other-pkg", "PyPI", _osv_range("ECOSYSTEM", "8.8.8")),
            _osv_affected("demo-pkg", "PyPI", _osv_range("GIT", "a" * 40)),
            _osv_affected("demo-pkg", "PyPI", _osv_range("SEMVER", "7.7.7")),
            _osv_affected(
                "demo-pkg",
                "PyPI",
                _osv_range("ECOSYSTEM", "0.9.0"),
                _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
            ),
        )
    )
    payloads.append(
        _osv_payload(
            {"package": {"name": "demo-pkg", "ecosystem": "PyPI"}, "versions": ["1.0.0"]},
            _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0")),
        )
    )

    for payload in payloads:
        _assert_event_semantics(payload)

    first_ranges = payloads[0]["vulns"][0]["affected"][0]["ranges"]
    assert first_ranges[0]["events"] == [{"introduced": "0"}, {"fixed": "0.9.0"}]
    assert first_ranges[1]["events"] == [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]


class _StaticSource(DependencySource):
    def __init__(self, dep):
        self.dep = dep

    def collect(self):
        yield self.dep

    def fix(self, _):
        raise NotImplementedError


_SYNTHETIC_OSV_URL = "https://osv.example.invalid/v1/query"


def _mock_versioned_feed(monkeypatch, payloads: dict):
    queried = []
    urls = []

    def post(url, data=None, **kwargs):
        urls.append(url)
        version = json.loads(data)["version"]
        queried.append(version)
        return pretend.stub(
            raise_for_status=lambda: None,
            json=lambda: payloads.get(version, {}),
        )

    osv = service.OsvService(osv_url=_SYNTHETIC_OSV_URL)
    monkeypatch.setattr(osv.session, "post", post)

    return osv, queried, urls


def _block_sockets(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", no_network)


def test_osv_ranges_resolver_upgrades_past_first_fix(monkeypatch):
    # End-to-end trace through the real OsvService, Auditor and resolve_fix_versions
    # with a per-version mock feed: the installed 1.0.0 is covered by the second
    # range, so the resolver must upgrade to 1.2.0 even though 0.9.0 comes first.
    _block_sockets(monkeypatch)

    payloads = {
        "1.0.0": _osv_payload(
            _osv_affected(
                "demo-pkg",
                "PyPI",
                _osv_range("ECOSYSTEM", "0.9.0"),
                _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
            )
        ),
        "1.2.0": {},
    }
    osv, queried, urls = _mock_versioned_feed(monkeypatch, payloads)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    audited = dict(Auditor(osv).audit(_StaticSource(dep)))
    assert len(audited[dep]) == 1

    fixes = list(resolve_fix_versions(osv, audited))

    assert fixes == [ResolvedFixVersion(dep=dep, version=Version("1.2.0"))]
    assert queried == ["1.0.0", "1.2.0"]
    assert urls == [_SYNTHETIC_OSV_URL, _SYNTHETIC_OSV_URL]


def test_osv_ranges_resolver_requeries_when_candidate_still_vulnerable(monkeypatch):
    # The resolver must not blindly accept a candidate fix version: 1.2.0 is still
    # reported vulnerable by the feed, so it has to be queried again and upgraded.
    _block_sockets(monkeypatch)

    payloads = {
        "1.0.0": _osv_payload(
            _osv_affected(
                "demo-pkg",
                "PyPI",
                _osv_range("ECOSYSTEM", "0.9.0"),
                _osv_range("ECOSYSTEM", "1.2.0", introduced="1.0.0"),
            )
        ),
        "1.2.0": _osv_payload(
            _osv_affected("demo-pkg", "PyPI", _osv_range("ECOSYSTEM", "1.3.0", introduced="1.2.0"))
        ),
        "1.3.0": {},
    }
    osv, queried, urls = _mock_versioned_feed(monkeypatch, payloads)

    dep = service.ResolvedDependency("demo-pkg", Version("1.0.0"))
    audited = dict(Auditor(osv).audit(_StaticSource(dep)))

    fixes = list(resolve_fix_versions(osv, audited))

    assert fixes == [ResolvedFixVersion(dep=dep, version=Version("1.3.0"))]
    assert queried == ["1.0.0", "1.2.0", "1.3.0"]
    assert urls == [_SYNTHETIC_OSV_URL] * 3
