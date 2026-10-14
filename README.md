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

## Extra detail in each report
- **Stack**: which Portainer/compose stack (and containers) use each image, plus a per-stack roll-up.
- **CVE age**: how long ago each CVE was published, the oldest per image, and how many are over a year old.
- **Unmaintained upstream**: no newer tag and the tag last published more than `STALE_DAYS` ago.
- **Alternatives**: for stale or end-of-life images, maintained replacements from `alternatives.json` are checked
  (exists, last published, CVE count at your severities). Add your own in `/data/alternatives.json` (same format).
- **Archive**: every run is saved as `reports/<YYYY-MM-DD_HHMMSS>/{report.txt,report.html,results.json}` (all CVEs, not the
  email's capped list) in the `monitor-data` volume, and optionally copied to a NAS.

### Archiving reports to a folder / NAS
Set `ARCHIVE_METHOD=local` and `ARCHIVE_LOCAL_DIR=/path/on/host` (e.g. a share on the Docker host). Give the container's user
(uid 10001) write access without changing ownership: `sudo setfacl -m u:10001:rwx /path/on/host`.
A failed copy is treated as an error: it is called out in the email and the heartbeat is withheld.
(Remote rsync/sftp upload was removed to keep the image free of ssh/rsync; mount the NAS on the host instead.)

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
- Distroless runtime image (Chainguard Python): no shell, no package manager, no ssh/rsync/skopeo; registry checks use a small built-in client.
- Scanner runs as non-root, read-only rootfs, all caps dropped, `no-new-privileges`, on an internal network to the proxy.
- No credentials in the image or repo; Trivy and base image versions pinned; weekly CI rebuild; the CI scans its own image.
- Scanning uses image *content* only; it never starts or modifies your containers.

## Also worth adding to your environment
See `docs/HARDENING.md`.

## License

MIT, see [LICENSE](LICENSE). Third-party components keep their own licenses (see CLAUDE.md > Attributions).
