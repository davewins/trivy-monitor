"""Save each run's report to a dated directory, optionally copying it to a NAS over rsync/ssh or sftp."""
import dataclasses
import json
import logging
import os
import shutil
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


def upload(cfg: Config, local_dir: Path, name: str) -> str:
    """Copy the run's directory to the host folder mounted at /archive. Raises on any failure."""
    if cfg.archive_method != "local":
        return ""
    target = Path(LOCAL_ARCHIVE_DIR)
    if not target.is_dir() or not os.access(target, os.W_OK):
        raise RuntimeError(f"{target} is not a writable directory; check ARCHIVE_LOCAL_DIR and its ownership (uid 10001)")
    shutil.copytree(local_dir, target / name)
    return f"{target / name} (host folder mounted at {LOCAL_ARCHIVE_DIR})"
