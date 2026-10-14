"""Save each run's report to a dated directory, optionally copying it to a NAS over rsync/ssh or sftp."""
import dataclasses
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from .config import Config

log = logging.getLogger("trivy-monitor")
LOCAL_ARCHIVE_DIR = "/archive"


def _default(o):
    if isinstance(o, set):
        return sorted(o)
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    return str(o)


def stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m-%d_%H%M%S")


def save_local(cfg: Config, name: str, text: str, html: str, results: list) -> Path:
    """Write report.txt/report.html/results.json into <state_dir>/reports/<name>/ and prune old runs."""
    root = Path(cfg.state_dir) / "reports"
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.txt").write_text(text)
    (d / "report.html").write_text(html)
    (d / "results.json").write_text(json.dumps(results, default=_default, indent=1))
    if cfg.archive_keep_local > 0:
        runs = sorted(p for p in root.iterdir() if p.is_dir())
        for old in runs[: -cfg.archive_keep_local]:
            shutil.rmtree(old, ignore_errors=True)
    return d


def _run(cmd: list[str], stdin: str | None = None) -> None:
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[-300:]}")


def ssh_options(cfg: Config, keyfile: str, known_hosts: str) -> list[str]:
    return ["-i", keyfile, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", f"UserKnownHostsFile={known_hosts}", "-o", "StrictHostKeyChecking=yes"]


def remote_dir(cfg: Config, name: str) -> str:
    return f"{cfg.archive_path.rstrip('/')}/{name}"


def upload(cfg: Config, local_dir: Path, name: str) -> str:
    """Copy local_dir to the NAS. Returns a human-readable destination. Raises on any failure."""
    if cfg.archive_method == "none":
        return ""
    if cfg.archive_method == "local":  # bind-mounted host folder (compose mounts it at /archive)
        target = Path(LOCAL_ARCHIVE_DIR)
        if not target.is_dir() or not os.access(target, os.W_OK):
            raise RuntimeError(f"{target} is not a writable directory; check ARCHIVE_LOCAL_DIR and its ownership (uid 10001)")
        shutil.copytree(local_dir, target / name)
        return f"{target / name} (host folder mounted at {LOCAL_ARCHIVE_DIR})"
    dest = remote_dir(cfg, name)
    with tempfile.TemporaryDirectory(prefix="archive-") as tmp:
        key, kh = os.path.join(tmp, "key"), os.path.join(tmp, "known_hosts")
        Path(key).write_text(cfg.archive_ssh_key.rstrip("\n") + "\n")
        os.chmod(key, 0o600)
        Path(kh).write_text(cfg.archive_known_hosts.rstrip("\n") + "\n")
        opts = ssh_options(cfg, key, kh)
        target = f"{cfg.archive_user}@{cfg.archive_host}"
        if cfg.archive_method == "rsync":
            ssh = "ssh -p {} {}".format(cfg.archive_port, " ".join(opts))
            _run(["rsync", "-rt", "--mkpath", "-e", ssh, f"{local_dir}/", f"{target}:{dest}/"])
        else:  # sftp batch: create each path component (ignore 'exists'), then put the files
            parts, cur, batch = [p for p in dest.split("/") if p], "", []
            for part in parts:
                cur += "/" + part
                batch.append(f"-mkdir {cur}")
            for f in sorted(local_dir.iterdir()):
                batch.append(f"put {f} {dest}/{f.name}")
            _run(["sftp", "-P", str(cfg.archive_port), *opts, "-b", "-", target], stdin="\n".join(batch) + "\n")
    return f"{cfg.archive_user}@{cfg.archive_host}:{dest}"
