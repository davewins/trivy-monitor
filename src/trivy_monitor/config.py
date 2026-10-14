"""Configuration, read entirely from environment variables.

Any variable NAME can alternatively be supplied as NAME_FILE (path to a file,
e.g. a Docker/Portainer secret) so credentials never need to live in a compose file.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def env(name: str, default: str = "") -> str:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text().strip()
    val = os.environ.get(name)
    return default if val is None or val == "" else val.strip()


def env_bool(name: str, default: bool) -> bool:
    return env(name, str(default)).lower() in ("1", "true", "yes", "on")


def env_list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in env(name, default).split(",") if x.strip()]


@dataclass
class Config:
    schedule: str = "0 6 * * 1"  # Mondays 06:00 (container TZ)
    run_on_start: bool = False
    docker_hosts: list[tuple[str, str]] = field(default_factory=list)
    include_stopped: bool = False
    severities: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    only_fixable: bool = False
    check_upstream: bool = True
    max_cves_per_image: int = 15
    ignore_images: list[str] = field(default_factory=list)
    caution_patterns: list[str] = field(default_factory=list)
    trivy_timeout: str = "10m"
    # email
    dry_run: bool = False
    send_clean_report: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # starttls | ssl | none
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_to: list[str] = field(default_factory=list)
    subject_prefix: str = "[trivy-monitor]"
    heartbeat_url: str = ""
    state_dir: str = "/data"
    instance_name: str = ""

    @classmethod
    def from_env(cls) -> "Config":
        hosts = []
        for item in env_list("DOCKER_HOSTS", "local=unix:///var/run/docker.sock"):
            name, _, url = item.partition("=")
            if not url:
                raise ValueError(f"DOCKER_HOSTS entry '{item}' must look like name=url")
            hosts.append((name.strip(), url.strip()))
        sev = [s.upper() for s in env_list("SEVERITIES", "CRITICAL,HIGH")]
        bad = [s for s in sev if s not in SEVERITY_ORDER]
        if bad:
            raise ValueError(f"Unknown SEVERITIES {bad}; valid: {SEVERITY_ORDER}")
        return cls(
            schedule=env("SCHEDULE_CRON", "0 6 * * 1"),
            run_on_start=env_bool("RUN_ON_START", False),
            docker_hosts=hosts,
            include_stopped=env_bool("INCLUDE_STOPPED", False),
            severities=sev,
            only_fixable=env_bool("ONLY_FIXABLE", False),
            check_upstream=env_bool("CHECK_UPSTREAM", True),
            max_cves_per_image=int(env("MAX_CVES_PER_IMAGE", "15")),
            ignore_images=env_list("IGNORE_IMAGES"),
            caution_patterns=[p.lower() for p in env_list(
                "CAUTION_PATTERNS",
                "pihole,bunkerweb,wg-easy,guacamole,backrest,postgres,mysql,mariadb,redis")],
            trivy_timeout=env("TRIVY_TIMEOUT", "10m"),
            dry_run=env_bool("DRY_RUN", False),
            send_clean_report=env_bool("SEND_CLEAN_REPORT", False),
            smtp_host=env("SMTP_HOST"),
            smtp_port=int(env("SMTP_PORT", "587")),
            smtp_security=env("SMTP_SECURITY", "starttls").lower(),
            smtp_user=env("SMTP_USER"),
            smtp_password=env("SMTP_PASSWORD"),
            mail_from=env("MAIL_FROM") or env("SMTP_USER"),
            mail_to=env_list("MAIL_TO"),
            subject_prefix=env("SUBJECT_PREFIX", "[trivy-monitor]"),
            heartbeat_url=env("HEARTBEAT_URL"),
            state_dir=env("STATE_DIR", "/data"),
            instance_name=env("INSTANCE_NAME"),
        )

    def validate(self) -> None:
        if self.dry_run:
            return
        missing = [n for n, v in (("SMTP_HOST", self.smtp_host),
                                  ("MAIL_FROM", self.mail_from),
                                  ("MAIL_TO", self.mail_to)) if not v]
        if missing:
            raise ValueError(f"Missing required settings: {', '.join(missing)} (or set DRY_RUN=true)")
        if self.smtp_security not in ("starttls", "ssl", "none"):
            raise ValueError("SMTP_SECURITY must be starttls, ssl or none")
