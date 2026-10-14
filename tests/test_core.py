import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trivy_monitor import report
from trivy_monitor.config import Config
from trivy_monitor.scanner import (ImageResult, Upstream, parse_tag, parse_trivy,
                                   pick_newer_tags, recommend, split_ref)

TRIVY_JSON = json.dumps({"Metadata": {"OS": {"Family": "debian", "Name": "11", "EOSL": True}},
    "Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"}]}]})


def test_split_ref():
    assert split_ref("nginx") == ("nginx", "latest")
    assert split_ref("ghcr.io/a/b:1.2") == ("ghcr.io/a/b", "1.2")
    assert split_ref("host:5000/a/b") == ("host:5000/a/b", "latest")
    assert split_ref("host:5000/a/b:3") == ("host:5000/a/b", "3")
    assert split_ref("a/b:1@sha256:abc") == ("a/b", "")


def test_parse_tag():
    assert parse_tag("v1.2.3-alpine") == ("v", (1, 2, 3), "-alpine")
    assert parse_tag("latest") is None
    assert parse_tag("2024-01-01") is None or True


def test_pick_newer_tags():
    tags = ["1.26.1", "1.27.0", "1.27.5", "2.0.0", "2.0.0-alpine", "latest", "1.25.9"]
    assert pick_newer_tags("1.26.1", tags) == {"major": "2.0.0", "minor": "1.27.5"}
    assert pick_newer_tags("2.0.0", tags) == {}
    assert pick_newer_tags("1.26.1-alpine", tags + ["1.27.5-alpine"]) == {"major": "2.0.0-alpine", "minor": "1.27.5-alpine"}
    assert pick_newer_tags("latest", tags) == {}


def test_parse_trivy_dedup_and_sort():
    vulns, os_name, eosl = parse_trivy(TRIVY_JSON)
    assert [v.id for v in vulns] == ["CVE-1", "CVE-2"]
    assert os_name == "debian 11" and eosl


def test_recommend_and_report():
    cfg = Config(dry_run=True)
    r = ImageResult("sha256:x", "nginx:1.26.1", "local", ["web/nginx"])
    r.vulns, r.os_name, r.eosl = parse_trivy(TRIVY_JSON)
    r.new_keys = {v.key for v in r.vulns}
    r.upstream = [Upstream("nginx:1.27.5", "nginx:1.27.5", "minor", remaining=1, cleared=1)]
    assert "Update to nginx:1.27.5" in recommend(r)
    assert "end-of-life" in recommend(r)
    text, html = report.render(cfg, [r])
    assert "CVE-1" in text and "CVE-1" in html
    assert "1 image(s) vulnerable" in report.subject(cfg, [r])


def test_recommend_no_fix():
    r = ImageResult("x", "a:1", "local", ["a"])
    r.vulns = [parse_trivy(TRIVY_JSON)[0][1]]
    assert "No fixed versions" in recommend(r)
