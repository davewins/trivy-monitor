"""Discover running images, scan with Trivy, and check upstream for fixes."""
import fnmatch
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

import docker

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

    @property
    def key(self) -> str:
        return f"{self.id}|{self.pkg}"


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
                label = c.labels.get("com.docker.compose.project", "")
                name = f"{label}/{c.name}" if label else c.name
                key = (host, iid)
                if key not in found:
                    found[key] = ImageResult(iid, ref, host, [])
                found[key].containers.append(name)
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
                      v.get("Title", ""), v.get("PrimaryURL", ""))
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


def remote_digest(ref: str) -> str:
    out = _run(["skopeo", "inspect", "--no-tags", f"docker://{ref}"], timeout=120)
    return json.loads(out)["Digest"]


def list_tags(repo: str) -> list[str]:
    return json.loads(_run(["skopeo", "list-tags", f"docker://{repo}"], timeout=120)).get("Tags", [])


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

    # 1) has the same tag been rebuilt upstream since we pulled it?
    try:
        local = local_repo_digests(host_url, r.image_id)
        if not local:
            r.upstream.append(Upstream("locally built image", r.ref, "rebuild",
                                       error="no registry digest; rebuild locally with a refreshed base image"))
            return
        else:
            digest = remote_digest(f"{repo}:{tag}")
            if not any(digest in d for d in local):
                evaluate(f"{repo}:{tag} (newer build of same tag)", f"{repo}:{tag}", "rebuild")
    except Exception as e:
        r.upstream.append(Upstream("registry check", r.ref, "rebuild", error=str(e)))

    # 2) is there a newer version tag?
    try:
        newer = pick_newer_tags(tag, list_tags(repo))
        minor, major = newer.get("minor"), newer.get("major")
        if minor:
            evaluate(f"{repo}:{minor} (newest in same major)", f"{repo}:{minor}", "minor")
        if major and major != minor:
            evaluate(f"{repo}:{major} (next major)", f"{repo}:{major}", "major")
    except Exception as e:
        log.info("tag listing failed for %s: %s", repo, e)


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
    if r.eosl:
        notes.append(f"Base OS {r.os_name} is end-of-life: move to a supported image variant.")
    if r.caution:
        notes.append("High blast-radius service: schedule the update and confirm before applying.")
    return " ".join(notes)
