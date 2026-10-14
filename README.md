# trivy-monitor

Weekly CVE monitoring for the containers running on your Docker hosts (built for Portainer).
It scans every running image with [Trivy](https://trivy.dev), emails you the CRITICAL/HIGH findings, and
tells you whether upstream already ships a fix and what to update.

## What the email tells you
- Per image: which containers/stacks use it, severity counts, which CVEs are **new** since last run, fixed package versions.
- **Recommendation**, worked out by actually scanning candidates:
  - the same tag was rebuilt upstream -> "pull and redeploy"
  - newest tag in the same major, and next major -> "update to X: clears N of M, K remain"
  - fixes exist for packages but no published image has them yet -> "wait / rebuild"
  - base OS end-of-life, or high blast-radius service (`CAUTION_PATTERNS`) -> called out.
- **Scan errors are emailed too**: an unreachable host, failed DB update or failed image scan is never reported as "clean".
  Zero containers discovered is treated as an error. Optional `HEARTBEAT_URL` (e.g. Uptime Kuma push) catches the case where the container itself dies.

## Deploy in Portainer
1. Push this repo to GitHub (public). The Actions workflow tests it and publishes `ghcr.io/<you>/trivy-monitor:latest`
   (make the package public, or add GHCR registry creds in Portainer).
2. Portainer > Stacks > Add stack > *Repository* (this repo, `docker-compose.yml`), or paste the compose in the web editor.
3. Under **Environment variables** enter the values from `.env.example` (`SMTP_*`, `MAIL_TO`, `TRIVY_MONITOR_IMAGE`...).
   Secrets live only in Portainer, never in git. For stricter handling use `SMTP_PASSWORD_FILE=/run/secrets/...`
   (every variable supports a `_FILE` form).
4. First run: set `RUN_ON_START=true` (and `DRY_RUN=true` if you want to read the report in the logs first), then set them back.

Test locally without email: `docker run --rm -e DRY_RUN=true -v /var/run/docker.sock:/var/run/docker.sock:ro ... --once`.

## Multiple hosts (e.g. a second Docker environment)
Simplest and safest: deploy this stack on each host (set `INSTANCE_NAME`). Alternatively list several in
`DOCKER_HOSTS=name=url,name2=url2`, but never expose a Docker API port on the LAN unauthenticated (use a socket proxy
bound to a firewalled address, or TLS).

## Settings
See `.env.example`. Key ones: `SEVERITIES` (default `CRITICAL,HIGH`), `SCHEDULE_CRON` (default Mon 06:00),
`ONLY_FIXABLE`, `CHECK_UPSTREAM`, `IGNORE_IMAGES`. Accepted risks: put CVE IDs in `/data/.trivyignore` (volume `monitor-data`).

## Security design
- Docker access only via a read-only **socket proxy** (no start/stop/exec/create); the scanner has no socket mount.
- Scanner runs as non-root, read-only rootfs, all caps dropped, `no-new-privileges`, on an internal network to the proxy.
- No credentials in the image or repo; Trivy and base image versions pinned; weekly CI rebuild; the CI scans its own image.
- Scanning uses image *content* only; it never starts or modifies your containers.

## Also worth adding to your environment
See `docs/HARDENING.md`.
