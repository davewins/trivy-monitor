# Further hardening ideas (beyond CVE scanning)

Quick wins
1. **Pin image tags/digests** in stacks instead of `:latest`, then let Renovate/Dependabot (or this report) drive reviewed updates.
2. **Update notifications**: Diun or WUD tell you when a new image exists (this tool tells you if it is *worth* it). Avoid unattended auto-update (Watchtower) on pihole/bunkerweb/wg-easy/databases.
3. **Trivy misconfig + secret scans** (`--scanners misconfig,secret`) over your compose/stack files: finds privileged containers, docker.sock mounts, missing healthchecks, committed secrets.
4. **Docker Bench for Security** / `docker-bench-security` periodically against each host.
5. **Host patching**: unattended-upgrades (security only) + `needrestart`, and watch kernel/Docker/containerd versions; Trivy only sees containers, not the host.

Container hardening, per stack
6. `read_only: true`, `cap_drop: [ALL]` (add back only what is needed), `no-new-privileges`, non-root `user:`, memory/pids limits.
7. Don't mount `/var/run/docker.sock` into apps; use a socket proxy where unavoidable (Portainer agent, Traefik, etc.).
8. Put internal-only services on `internal: true` networks; publish ports on specific interfaces (`127.0.0.1:` or LAN IP) not `0.0.0.0`.
9. Keep secrets in Docker/Portainer secrets or `_FILE` vars; never in compose files in git. Run **gitleaks** in CI/pre-commit on public repos.

Network / access
10. Verify bunkerweb/WAF is the *only* ingress; scan your WAN IP externally (`nmap`) occasionally to confirm.
11. Enforce 2FA/SSO (Authelia/Authentik) on admin UIs; Portainer behind VPN only, with strong admin password and API tokens scoped/rotated.
12. Fail2ban/CrowdSec on the host and the reverse proxy.

Resilience & detection
13. **Backups with restore tests** (backrest): a monthly restore drill; alert on backup failure (Kuma push) rather than success-by-silence.
14. Centralised logs/alerts: Loki or Dozzle + alerts for auth failures, container restart loops; Kuma heartbeats for every cron-like job.
15. Image provenance: prefer verified/official images, pin by digest, optionally verify signatures with `cosign` where publishers sign.
