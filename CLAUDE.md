# trivy-monitor: guidance for AI assistants and contributors

Weekly Trivy CVE scan of running Docker containers (deployed via Portainer), emailing findings with
upstream-fix recommendations. This repo is **public**: never commit secrets, hostnames, IPs, or real email addresses.

## Layout
- `src/trivy_monitor/config.py`: all settings come from env vars (each also accepts `NAME_FILE`).
- `scanner.py`: container discovery, Trivy invocation, upstream checks, recommendations.
- `registry.py`: tiny anonymous OCI registry client (digests, created date, tags). `archive.py`: dated report dirs.
- `report.py` / `mailer.py`: email rendering and SMTP / heartbeat.
- `main.py`: cron scheduler loop and `--once` mode. `docker-compose.yml`: Portainer stack (with read-only socket proxy).
- `tests/`: pytest unit tests (no Docker, Trivy or network needed).

## Rules
- Config only via environment variables; add new ones to `config.py`, `docker-compose.yml`, `.env.example` and the README.
- Never report "clean" when something could not be verified: DB update failure, unreachable host, failed scan,
  or zero containers must produce an error email. Keep this property when changing `main.py`.
- Count and display unique CVE IDs, not Trivy's per-package rows.
- Keep the security posture: non-root, read-only rootfs, `cap_drop: ALL`, no direct docker.sock in the scanner
  (socket proxy only, `POST=0`), pinned image/action/dependency versions. Verify a version or tag exists before pinning.
- The tool is read-only toward the environment: it must never start, stop, or modify containers.

## Develop and test
The runtime image is distroless (no shell/pip), so run tests in the matching `-dev` image:
```
docker run --rm --user root -v "$PWD:/w" -w /w --entrypoint sh cgr.dev/chainguard/python:latest-dev \
  -c "pip install -q --root-user-action=ignore --target /tmp/lib -r requirements.txt pytest && PYTHONPATH=/tmp/lib:/w/src python -m pytest -q tests"
docker build -t trivy-monitor:dev .
# end-to-end without email (reads the local Docker daemon):
docker run --rm --read-only --tmpfs /tmp --user 10001 --group-add "$(stat -c %g /var/run/docker.sock)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -v tm-cache:/cache -v tm-data:/data \
  -e DRY_RUN=true trivy-monitor:dev --once
```
A full scan of ~50 images takes about 15 minutes (mostly Trivy image export and scanning).
Keep the image's CVE count near zero: scan it (`trivy image`) after base/Trivy bumps; the weekly CI rebuild picks up base fixes.

## Attributions
- Built with [Claude Code](https://claude.com/claude-code) (Claude Sonnet 5.5) in collaboration with the repository owner;
  commits carry a `Co-Authored-By: Claude` trailer.
- [Trivy](https://github.com/aquasecurity/trivy) by Aqua Security, Apache-2.0: the vulnerability scanner copied into the image.
- [Chainguard Images](https://images.chainguard.dev) (Python, Apache-2.0): distroless runtime and build base.
- [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) by Tecnativa, Apache-2.0: read-only Docker API proxy.
- [docker-py](https://github.com/docker/docker-py), Apache-2.0, and [croniter](https://github.com/pallets-eco/croniter), MIT: Python dependencies.
- Vulnerability data comes from Trivy DB, which aggregates NVD, distro security trackers and GitHub advisories.
