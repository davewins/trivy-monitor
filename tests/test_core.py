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


# ---- age, stacks, alternatives, archive ----
from datetime import datetime, timedelta, timezone

from trivy_monitor import archive
from trivy_monitor.scanner import Alt, days_since, human_age, load_alternatives, norm_repo


def test_age_helpers():
    old = (datetime.now(timezone.utc) - timedelta(days=800)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 799 <= days_since(old) <= 801
    assert days_since("") is None and days_since("garbage") is None
    assert human_age(10) == "10d" and human_age(200) == "6mo" and human_age(800) == "2.2y" and human_age(None) == "?"


def test_alternatives_lookup(tmp_path):
    cfg = Config(state_dir=str(tmp_path))
    (tmp_path / "alternatives.json").write_text('{"Foo/Bar": ["baz/qux"]}')
    table = load_alternatives(cfg)
    assert table["atmoz/sftp"][0] == "drakkan/sftpgo"          # bundled
    assert table["foo/bar"] == ["baz/qux"]                      # user-supplied, normalised
    assert norm_repo("docker.io/library/Redis") == "redis"


def test_report_shows_stack_age_alternative():
    cfg = Config(dry_run=True)
    r = ImageResult("sha256:x", "atmoz/sftp:latest", "local", ["files/sftp"], stacks=["files"])
    v, _, _ = parse_trivy(TRIVY_JSON.replace('"Severity": "HIGH"', '"Severity": "HIGH", "PublishedDate": "2020-01-01T00:00:00Z"'))
    r.vulns = v
    r.stale, r.last_published_days = True, 800
    r.alternatives = [Alt("drakkan/sftpgo:latest", 20, 3, 0, 3)]
    text, html = report.render(cfg, [r])
    assert "BY STACK" in text and "files" in text
    assert "oldest CVE" in text and "alternative drakkan/sftpgo" in text
    assert "unmaintained" in recommend(r) and "drakkan/sftpgo" in recommend(r)


def test_archive_local_and_retention(tmp_path):
    cfg = Config(state_dir=str(tmp_path), archive_keep_local=2)
    for i in range(4):
        d = archive.save_local(cfg, f"2026-01-0{i + 1}_000000", "t", "<p>h</p>", [])
    names = sorted(p.name for p in (tmp_path / "reports").iterdir())
    assert names == ["2026-01-03_000000", "2026-01-04_000000"]
    assert (d / "report.txt").read_text() == "t" and (d / "results.json").exists()
    assert archive.remote_dir(Config(archive_path="/a/b/"), "X") == "/a/b/X"
    assert len(archive.stamp(datetime(2026, 10, 19, 6, 0, 12))) == 17


def test_archive_config_validation():
    import pytest
    with pytest.raises(ValueError):
        Config(archive_method="rsync").validate()
    with pytest.raises(ValueError):
        Config(archive_method="ftp").validate()
    Config(archive_method="none", dry_run=True).validate()
