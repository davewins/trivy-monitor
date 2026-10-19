"""Discover running images, scan with Trivy, and check upstream for fixes."""
import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

import docker

from . import registry
from .config import SEVERITY_ORDER, Config

log = logging.getLogger("trivy-monitor")


@dataclass
class Vuln:
    id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    title: str = ""
    url: str = ""
    published: str = ""

    @property
    def age_days(self) -> int | None:
        return days_since(self.published)

    @property
    def key(self) -> str:
        return f"{self.id}|{self.pkg}"


def days_since(iso: str) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


def human_age(days: int | None) -> str:
    if days is None:
        return "?"
    if days < 60:
        return f"{days}d"
    if days < 730:
        return f"{days // 30}mo"
    return f"{days / 365:.1f}y"


@dataclass
class Alt:
    ref: str
    last_published_days: int | None = None
    cves: int | None = None
    critical: int = 0
    high: int = 0
    error: str = ""


@dataclass
class Upstream:
    label: str          # e.g. "same tag, newer build" / "nginx:1.27.5 (patch/minor)"
    ref: str
    kind: str           # rebuild | minor | major
    remaining: int = 0
    cleared: int = 0
    error: str = ""


@dataclass
class ImageResult:
    image_id: str
    ref: str
    host: str
    containers: list[str]
    vulns: list[Vuln] = field(default_factory=list)
    os_name: str = ""
    eosl: bool = False
    error: str = ""
    upstream: list[Upstream] = field(default_factory=list)
    new_keys: set = field(default_factory=set)
    caution: bool = False
    stacks: list[str] = field(default_factory=list)
    last_published_days: int | None = None   # registry build date of the tag we run
    stale: bool = False
    alternatives: list[Alt] = field(default_factory=list)

    @property
    def oldest_cve_days(self) -> int | None:
        ages = [v.age_days for v in self.vulns if v.age_days is not None]
        return max(ages) if ages else None

    @property
    def old_cves(self) -> int:
        """Unique CVEs published more than a year ago."""
        return len({v.id for v in self.vulns if (v.age_days or 0) > 365})

    def by_cve(self) -> list[tuple[Vuln, list[str]]]:
        """One row per CVE id (worst/first Vuln, all affected packages), already sorted."""
        rows: dict[str, tuple[Vuln, list[str]]] = {}
        for v in self.vulns:
            if v.id not in rows:
                rows[v.id] = (v, [])
            elif v.fixed and not rows[v.id][0].fixed:
                rows[v.id] = (v, rows[v.id][1])
            rows[v.id][1].append(v.pkg)
        return list(rows.values())

    @property
    def fixable(self) -> int:
        return sum(1 for v, _ in self.by_cve() if v.fixed)

    @property
    def cve_count(self) -> int:
        return len({v.id for v in self.vulns})


# ---------- docker discovery ----------

def discover(cfg: Config) -> dict[tuple[str, str], ImageResult]:
    """Return one ImageResult per (host, image id), listing the containers using it."""
    found: dict[tuple[str, str], ImageResult] = {}
    for host, url in cfg.docker_hosts:
        try:
            client = docker.DockerClient(base_url=url, timeout=30)
            for c in client.containers.list(all=cfg.include_stopped):
                ref = c.attrs["Config"]["Image"]
                if any(fnmatch.fnmatch(ref, p) for p in cfg.ignore_images):
                    continue
                iid = c.attrs["Image"]
                label = c.labels.get("com.docker.compose.project") or c.labels.get("com.docker.stack.namespace") or ""
                name = f"{label}/{c.name}" if label else c.name
                key = (host, iid)
                if key not in found:
                    found[key] = ImageResult(iid, ref, host, [])
                found[key].containers.append(name)
                if (label or "(standalone)") not in found[key].stacks:
                    found[key].stacks.append(label or "(standalone)")
        except Exception as e:  # one unreachable host must not hide the others
            log.error("host %s unreachable: %s", host, e)
            found[(host, "unreachable")] = ImageResult(
                "unreachable", f"(host {host})", host, [], error=f"Docker host unreachable: {e}")
    for r in found.values():
        low = (r.ref + " " + " ".join(r.containers)).lower()
        r.caution = any(p in low for p in cfg.caution_patterns)
    return found


# ---------- trivy ----------

def _run(cmd: list[str], env: dict | None = None, timeout: int = 900) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **(env or {})})
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip()[-500:] or f"exit {p.returncode}")
    return p.stdout


def purge_stale_tmp() -> int:
    """Remove trivy-* scratch dirs a killed trivy left in the (disk-backed) temp dir.
    Only call between scans: nothing else is running trivy then. Returns the count removed."""
    n = 0
    for d in Path(tempfile.gettempdir()).glob("trivy-*"):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
            n += 1
    if n:
        log.info("removed %d stale trivy temp dir(s) from a previous killed scan", n)
    return n


def update_db(cfg: Config) -> None:
    _run(["trivy", "image", "--download-db-only", "--quiet"], timeout=600)


def trivy_scan(cfg: Config, target: str, source: str, docker_url: str = "") -> tuple[list[Vuln], str, bool]:
    cmd = ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln",
           "--skip-db-update", "--image-src", source, "--timeout", cfg.trivy_timeout,
           "--severity", ",".join(cfg.severities)]
    if cfg.only_fixable:
        cmd.append("--ignore-unfixed")
    ignorefile = os.path.join(cfg.state_dir, ".trivyignore")
    if os.path.exists(ignorefile):
        cmd += ["--ignorefile", ignorefile]
    cmd.append(target)
    env = {"DOCKER_HOST": docker_url} if docker_url else {}
    return parse_trivy(_run(cmd, env))


def scan_image(cfg: Config, r: ImageResult, host_url: str) -> tuple[list[Vuln], str, bool]:
    """Scan via the Docker daemon; if its image export is broken (seen with images carrying
    attestation manifests), fall back to scanning the exact digest from the registry."""
    try:
        return trivy_scan(cfg, r.image_id, "docker", host_url)
    except Exception as first:
        digests = []
        try:
            digests = local_repo_digests(host_url, r.image_id)
        except Exception:
            pass
        if not digests:
            raise
        log.warning("%s: daemon export failed (%s); retrying from registry", r.ref, str(first)[-120:])
        return trivy_scan(cfg, digests[0], "remote")


def parse_trivy(raw: str) -> tuple[list[Vuln], str, bool]:
    data = json.loads(raw)
    meta_os = (data.get("Metadata") or {}).get("OS") or {}
    os_name = f"{meta_os.get('Family', '')} {meta_os.get('Name', '')}".strip()
    seen, vulns = set(), []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            vv = Vuln(v["VulnerabilityID"], v.get("PkgName", ""), v.get("InstalledVersion", ""),
                      v.get("FixedVersion", ""), v.get("Severity", "UNKNOWN"),
                      v.get("Title", ""), v.get("PrimaryURL", ""), v.get("PublishedDate", ""))
            if vv.key not in seen:
                seen.add(vv.key)
                vulns.append(vv)
    vulns.sort(key=lambda v: (-SEVERITY_ORDER.index(v.severity) if v.severity in SEVERITY_ORDER else 0,
                              not v.fixed, v.id))
    return vulns, os_name, bool(meta_os.get("EOSL"))


# ---------- upstream checks ----------

TAG_RE = re.compile(r"^(?P<prefix>v?)(?P<ver>\d+(?:\.\d+)*)(?P<suffix>(?:[-_.][A-Za-z].*)?)$")


def split_ref(ref: str) -> tuple[str, str]:
    """'ghcr.io/x/y:1.2' -> ('ghcr.io/x/y', '1.2'). Digest-pinned refs return tag ''."""
    base, at, _ = ref.partition("@")
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        base, _, tag = base.rpartition(":")
    else:
        tag = "latest"
    return base, ("" if at else tag)


def parse_tag(tag: str):
    m = TAG_RE.match(tag)
    if not m:
        return None
    return m["prefix"], tuple(int(x) for x in m["ver"].split(".")), m["suffix"]


def pick_newer_tags(current: str, tags: list[str]) -> dict[str, str]:
    """Best newer tag overall, and best within the same major, with identical shape/suffix."""
    cur = parse_tag(current)
    if not cur:
        return {}
    prefix, ver, suffix = cur
    cands = []
    for t in tags:
        p = parse_tag(t)
        if p and p[0] == prefix and p[2] == suffix and len(p[1]) == len(ver) and p[1] > ver:
            cands.append((p[1], t))
    if not cands:
        return {}
    cands.sort()
    out = {"major": cands[-1][1]}
    same_major = [c for c in cands if c[0][0] == ver[0]]
    if same_major:
        out["minor"] = same_major[-1][1]
    return out


def remote_info(ref: str) -> tuple[set[str], str]:
    """(digests identifying the image in its registry, created ISO date)."""
    return registry.info(ref)


def list_tags(repo: str) -> list[str]:
    return registry.tags(repo)


def local_repo_digests(host_url: str, image_id: str) -> list[str]:
    client = docker.DockerClient(base_url=host_url, timeout=30)
    return client.images.get(image_id).attrs.get("RepoDigests") or []


def check_upstream(cfg: Config, r: ImageResult, host_url: str) -> None:
    repo, tag = split_ref(r.ref)
    current_keys = {v.id for v in r.vulns}
    if not tag:
        r.upstream.append(Upstream("pinned by digest", r.ref, "rebuild",
                                   error="image is digest-pinned; cannot compare upstream tags"))
        return

    def evaluate(label: str, ref: str, kind: str):
        u = Upstream(label, ref, kind)
        try:
            vulns, _, _ = trivy_scan(cfg, ref, "remote")
            new_keys = {v.id for v in vulns}
            u.remaining = len(new_keys)
            u.cleared = len(current_keys - new_keys)
        except Exception as e:
            u.error = str(e)
        r.upstream.append(u)

    # 1) has the same tag been rebuilt upstream since we pulled it? (also tells us when it was last published)
    registry_ok = False
    try:
        local = local_repo_digests(host_url, r.image_id)
        if not local:
            r.upstream.append(Upstream("locally built image", r.ref, "rebuild",
                                       error="no registry digest; rebuild locally with a refreshed base image"))
            return
        digests, created = remote_info(f"{repo}:{tag}")
        registry_ok = True
        r.last_published_days = days_since(created)
        if not any(d in loc for d in digests for loc in local):
            evaluate(f"{repo}:{tag} (newer build of same tag)", f"{repo}:{tag}", "rebuild")
    except Exception as e:
        r.upstream.append(Upstream("registry check", r.ref, "rebuild", error=str(e)))
        return  # image not found / not readable anonymously: tag and staleness checks would be guesses

    # 2) is there a newer version tag?
    newer = {}
    try:
        newer = pick_newer_tags(tag, list_tags(repo))
        minor, major = newer.get("minor"), newer.get("major")
        if minor:
            evaluate(f"{repo}:{minor} (newest in same major)", f"{repo}:{minor}", "minor")
        if major and major != minor:
            evaluate(f"{repo}:{major} (next major)", f"{repo}:{major}", "major")
    except Exception as e:
        log.info("tag listing failed for %s: %s", repo, e)

    # 3) is the project itself still publishing? (nothing newer, and the tag has not been rebuilt in ages)
    rebuilt = any(u.kind == "rebuild" and not u.error for u in r.upstream)
    if registry_ok and not newer and not rebuilt and (r.last_published_days or 0) > cfg.stale_days:
        r.stale = True
    if cfg.suggest_alternatives and (r.stale or r.eosl):
        suggest_alternatives(cfg, r)


# ---------- alternatives ----------

def norm_repo(repo: str) -> str:
    repo = repo.lower()
    for pre in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if repo.startswith(pre):
            repo = repo[len(pre):]
    return repo[len("library/"):] if repo.startswith("library/") else repo


def load_alternatives(cfg: Config) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    for path in (Path(__file__).with_name("alternatives.json"), Path(cfg.state_dir) / "alternatives.json"):
        try:
            table.update({norm_repo(k): v for k, v in json.loads(path.read_text()).items() if not k.startswith("_")})
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("could not read %s: %s", path, e)
    return table


def suggest_alternatives(cfg: Config, r: ImageResult) -> None:
    repo, _ = split_ref(r.ref)
    for alt_ref in load_alternatives(cfg).get(norm_repo(repo), [])[:3]:
        base, tag = split_ref(alt_ref)
        ref = f"{base}:{tag or 'latest'}"
        a = Alt(ref)
        try:
            _, created = remote_info(ref)
            a.last_published_days = days_since(created)
            vulns, _, _ = trivy_scan(cfg, ref, "remote")
            a.cves = len({v.id for v in vulns})
            a.critical = len({v.id for v in vulns if v.severity == "CRITICAL"})
            a.high = len({v.id for v in vulns if v.severity == "HIGH"})
        except Exception as e:
            a.error = str(e)[-200:]
        r.alternatives.append(a)


def recommend(r: ImageResult) -> str:
    if r.error:
        return "Scan failed - investigate."
    if not r.vulns:
        return ""
    good = [u for u in r.upstream if not u.error and u.cleared > 0]
    good.sort(key=lambda u: (u.remaining, {"rebuild": 0, "minor": 1, "major": 2}[u.kind]))
    notes = []
    if good:
        b = good[0]
        verb = {"rebuild": "Pull and redeploy (no tag change)", "minor": "Update to",
                "major": "Major upgrade to (read the changelog first)"}[b.kind]
        notes.append(f"{verb} {b.ref}: clears {b.cleared} of "
                     f"{r.cve_count} CVEs, {b.remaining} would remain.")
    elif r.fixable:
        notes.append(f"{r.fixable} CVEs have a fixed package version, but no published upstream image "
                     "contains them yet. Re-check next run or rebuild if you build this image yourself.")
    else:
        notes.append("No fixed versions published for these findings yet. Consider limiting exposure "
                     "(network, auth) until upstream ships a fix.")
    if r.stale:
        notes.append(f"Upstream looks unmaintained: this tag was last published {human_age(r.last_published_days)} ago "
                     "and no newer version exists, so fixes are unlikely.")
    good_alts = sorted((a for a in r.alternatives if not a.error), key=lambda a: a.cves if a.cves is not None else 1e9)
    if good_alts:
        a = good_alts[0]
        notes.append(f"Consider migrating to {a.ref} (published {human_age(a.last_published_days)} ago, "
                     f"{a.critical} critical / {a.high} high). It is a different image: review its config and volumes first.")
    if r.eosl:
        notes.append(f"Base OS {r.os_name} is end-of-life: move to a supported image variant.")
    if r.caution:
        notes.append("High blast-radius service: schedule the update and confirm before applying.")
    return " ".join(notes)
