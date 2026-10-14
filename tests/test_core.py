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
    assert len(archive.stamp(datetime(2026, 10, 19, 6, 0, 12))) == 17


def test_archive_config_validation():
    import pytest
    with pytest.raises(ValueError):
        Config(archive_method="rsync").validate()      # ssh modes were removed
    Config(archive_method="none", dry_run=True).validate()


def test_archive_local_method(tmp_path, monkeypatch):
    import pytest
    cfg = Config(state_dir=str(tmp_path / "state"), archive_method="local")
    Config(archive_method="local", dry_run=True).validate()      # needs no host/key settings
    d = archive.save_local(cfg, "2026-01-01_000000", "t", "h", [])
    dest = tmp_path / "nas"
    monkeypatch.setattr(archive, "LOCAL_ARCHIVE_DIR", str(dest))
    with pytest.raises(RuntimeError):                            # missing mount must fail loudly
        archive.upload(cfg, d, d.name)
    dest.mkdir()
    assert "2026-01-01_000000" in archive.upload(cfg, d, d.name)
    assert (dest / "2026-01-01_000000" / "report.txt").read_text() == "t"


# ---- registry client (no network: _fetch is faked) ----
import hashlib

from trivy_monitor import registry


def test_parse_ref():
    assert registry.parse_ref("nginx") == ("registry-1.docker.io", "library/nginx", "latest")
    assert registry.parse_ref("louislam/uptime-kuma:2") == ("registry-1.docker.io", "louislam/uptime-kuma", "2")
    assert registry.parse_ref("ghcr.io/a/b:1.2") == ("ghcr.io", "a/b", "1.2")
    assert registry.parse_ref("host:5000/a/b") == ("host:5000", "a/b", "latest")
    assert registry.parse_ref("docker.io/library/redis:7") == ("registry-1.docker.io", "library/redis", "7")
    assert registry.parse_ref("a/b@sha256:abc")[2] == "sha256:abc"


def _fake_registry(monkeypatch, pages=1):
    import json as j
    cfg = j.dumps({"created": "2024-07-14T12:14:40Z"}).encode()
    cfg_d = "sha256:" + hashlib.sha256(cfg).hexdigest()
    man = j.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": cfg_d}}).encode()
    man_d = "sha256:" + hashlib.sha256(man).hexdigest()
    idx = j.dumps({"mediaType": registry.INDEX_TYPES[0], "manifests": [
        {"digest": "sha256:attest", "platform": {"os": "unknown", "architecture": "unknown"}},
        {"digest": man_d, "platform": {"os": "linux", "architecture": registry.ARCH.get(__import__("platform").machine().lower(), "amd64")}}]}).encode()
    calls = []

    def fake(url, headers):
        calls.append((url, headers.get("Authorization")))
        if "/token" in url:
            return 200, {}, b'{"token": "T"}'
        if url == "https://cdn.example/blob":
            assert "Authorization" not in headers          # token must not leak to the CDN
            return 200, {}, cfg
        if headers.get("Authorization") is None and "/tags/" not in url:
            return 401, {"WWW-Authenticate": 'Bearer realm="https://auth.example/token",service="reg"'}, b""
        if url.endswith("/manifests/latest"):
            return 200, {"Docker-Content-Digest": "sha256:topindex"}, idx
        if url.endswith("/manifests/" + man_d):
            return 200, {"Docker-Content-Digest": man_d}, man
        if url.endswith("/blobs/" + cfg_d):
            return 307, {"Location": "https://cdn.example/blob"}, b""
        if "/tags/list" in url:
            n = int(url.split("page=")[1]) if "page=" in url else 0
            link = f'</v2/a/b/tags/list?n=1000&page={n + 1}>; rel="next"' if n + 1 < pages else ""
            return 200, {"Link": link}, j.dumps({"tags": [f"1.{n}"]}).encode()
        return 404, {}, b""
    monkeypatch.setattr(registry, "_fetch", fake)
    registry._tokens.clear()
    return man_d


def test_registry_info_index_token_and_cdn(monkeypatch):
    man_d = _fake_registry(monkeypatch)
    digests, created = registry.info("ghcr.io/a/b:latest")
    assert digests == {"sha256:topindex", man_d} and created.startswith("2024-07-14")


def test_registry_tags_pagination_and_cap(monkeypatch):
    import pytest
    _fake_registry(monkeypatch, pages=3)
    assert registry.tags("ghcr.io/a/b") == ["1.0", "1.1", "1.2"]
    _fake_registry(monkeypatch, pages=registry.MAX_TAG_PAGES + 5)
    with pytest.raises(registry.RegistryError):
        registry.tags("ghcr.io/a/b")                       # refuse to act on a truncated list
