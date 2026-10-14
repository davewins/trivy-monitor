"""Minimal read-only OCI/Docker registry client (anonymous pull tokens only).

Replaces skopeo so the runtime image needs no OS tooling. Supports Docker Hub, ghcr.io, quay.io and any
registry using the standard Bearer-token flow. Private registries needing credentials raise RegistryError.
"""
import hashlib
import json
import platform
import re
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30
MAX_TAG_PAGES = 100  # x1000 tags; bigger repos are skipped rather than truncated
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
ACCEPT = ", ".join(INDEX_TYPES + ("application/vnd.oci.image.manifest.v1+json",
                                  "application/vnd.docker.distribution.manifest.v2+json"))
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm"}


class RegistryError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # surface 3xx so blob redirects can be followed WITHOUT our token
        return None


_opener = urllib.request.build_opener(_NoRedirect)
_tokens: dict[tuple[str, str], str] = {}


def parse_ref(ref: str) -> tuple[str, str, str]:
    """-> (api host, repository, tag-or-digest). 'nginx' -> ('registry-1.docker.io', 'library/nginx', 'latest')."""
    name, at, digest = ref.partition("@")
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "registry-1.docker.io", name
    if host in ("docker.io", "index.docker.io"):
        host = "registry-1.docker.io"
    tag = "latest"
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, _, tag = path.rpartition(":")
    if host == "registry-1.docker.io" and "/" not in path:
        path = "library/" + path
    return host, path, (digest if at else tag)


def _fetch(url: str, headers: dict) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except urllib.error.URLError as e:
        raise RegistryError(f"cannot reach {url.split('/v2/')[0]}: {e.reason}")


def _get_token(www_auth: str, repo: str) -> str:
    if not www_auth.lower().startswith("bearer"):
        raise RegistryError("registry requires credentials (only anonymous access is supported)")
    p = dict(re.findall(r'(\w+)="([^"]*)"', www_auth))
    q = {"scope": p.get("scope") or f"repository:{repo}:pull"}
    if p.get("service"):
        q["service"] = p["service"]
    status, _, body = _fetch(f"{p['realm']}?{urllib.parse.urlencode(q)}", {})
    if status != 200:
        raise RegistryError(f"token request denied ({status}): image may be private or not exist")
    d = json.loads(body)
    return d.get("token") or d.get("access_token") or ""


def _get(host: str, repo: str, path: str, accept: str = "*/*") -> tuple[int, dict, bytes]:
    url = path if path.startswith("http") else f"https://{host}{path}"
    for attempt in (0, 1):
        h = {"Accept": accept}
        if (host, repo) in _tokens:
            h["Authorization"] = f"Bearer {_tokens[(host, repo)]}"
        status, headers, body = _fetch(url, h)
        if status == 401 and attempt == 0:
            hdrs = {k.lower(): v for k, v in headers.items()}
            _tokens[(host, repo)] = _get_token(hdrs.get("www-authenticate", ""), repo)
            continue
        return status, {k.lower(): v for k, v in headers.items()}, body
    raise RegistryError("authentication failed")


def _manifest(host: str, repo: str, ref: str) -> tuple[str, dict]:
    status, h, body = _get(host, repo, f"/v2/{repo}/manifests/{ref}", ACCEPT)
    if status != 200:
        raise RegistryError(f"manifest {repo}:{ref} -> HTTP {status}")
    return h.get("docker-content-digest") or "sha256:" + hashlib.sha256(body).hexdigest(), json.loads(body)


def _blob(host: str, repo: str, digest: str) -> bytes:
    status, h, body = _get(host, repo, f"/v2/{repo}/blobs/{digest}")
    if status in (301, 302, 303, 307, 308):  # CDN redirect: fetch without our Authorization header
        status, _, body = _fetch(h["location"], {})
    if status != 200:
        raise RegistryError(f"blob {digest[:19]} -> HTTP {status}")
    return body


def info(ref: str) -> tuple[set[str], str]:
    """({digests that identify this image: index and platform manifest}, created ISO timestamp)."""
    host, repo, tag = parse_ref(ref)
    top, m = _manifest(host, repo, tag)
    digests = {top}
    if m.get("mediaType") in INDEX_TYPES or "manifests" in m:
        arch = ARCH.get(platform.machine().lower(), "amd64")
        pick = next((x for x in m["manifests"] if (x.get("platform") or {}).get("os") == "linux"
                     and x["platform"].get("architecture") == arch), None)
        if not pick:
            raise RegistryError(f"no linux/{arch} image in {ref}")
        digests.add(pick["digest"])
        _, m = _manifest(host, repo, pick["digest"])
        digests.add(_)
    created = json.loads(_blob(host, repo, m["config"]["digest"])).get("created", "")
    return digests, created


def tags(ref: str) -> list[str]:
    host, repo, _ = parse_ref(ref)
    out, path = [], f"/v2/{repo}/tags/list?n=1000"
    for _ in range(MAX_TAG_PAGES):
        status, h, body = _get(host, repo, path)
        if status != 200:
            raise RegistryError(f"tag list {repo} -> HTTP {status}")
        out += json.loads(body).get("tags") or []
        m = re.search(r'<([^>]+)>;\s*rel="next"', h.get("link", ""))
        if not m:
            return out
        path = m.group(1) if m.group(1).startswith(("/", "http")) else "/" + m.group(1)
    # A partial list could make us recommend the wrong "newest" version, so refuse instead of guessing.
    raise RegistryError(f"{repo} has more than {MAX_TAG_PAGES * 1000} tags; skipping newer-tag search")
