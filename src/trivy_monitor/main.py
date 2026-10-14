import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from croniter import croniter

from . import mailer, report, scanner
from .config import Config

log = logging.getLogger("trivy-monitor")
HEALTH = "/tmp/healthy"


def touch_health():
    Path(HEALTH).touch()


def load_state(cfg: Config) -> dict:
    try:
        return json.loads((Path(cfg.state_dir) / "state.json").read_text())
    except Exception:
        return {}


def save_state(cfg: Config, state: dict) -> None:
    try:
        (Path(cfg.state_dir) / "state.json").write_text(json.dumps(state))
    except Exception as e:
        log.warning("could not save state (new/old tracking disabled): %s", e)


def run_scan(cfg: Config) -> int:
    """Run one full scan. Returns process-style exit code (0 ok)."""
    log.info("scan starting")
    state = load_state(cfg)
    prev = {k: set(v) for k, v in state.get("seen", {}).items()}
    try:
        scanner.update_db(cfg)
    except Exception as e:
        # Never fail silently: tell the user the scanner itself is broken.
        mailer.send(cfg, "SCANNER ERROR: could not update Trivy database",
                    f"Trivy vulnerability DB update failed, nothing was scanned:\n{e}",
                    f"<p>Trivy vulnerability DB update failed, nothing was scanned:</p><pre>{e}</pre>")
        return 1

    found = scanner.discover(cfg)
    urls = dict(cfg.docker_hosts)
    results = []
    for (host, iid), r in found.items():
        if not r.error:
            try:
                r.vulns, r.os_name, r.eosl = scanner.scan_image(cfg, r, urls[host])
                if cfg.check_upstream and r.vulns:
                    scanner.check_upstream(cfg, r, urls[host])
            except Exception as e:
                r.error = f"trivy failed: {e}"
                log.error("%s: %s", r.ref, r.error)
        results.append(r)
        touch_health()

    new_state = {}
    for r in results:
        k = f"{r.host}|{r.ref}"
        keys = {v.key for v in r.vulns}
        r.new_keys = keys - prev.get(k, set()) if k in prev else keys
        if not r.error:
            new_state[k] = sorted(keys)
        elif k in prev:
            new_state[k] = sorted(prev[k])
    save_state(cfg, {"seen": new_state})

    findings = any(r.vulns for r in results)
    errors = any(r.error for r in results)
    if not results:
        errors = True
        log.error("no containers discovered - refusing to report all-clear")
    if findings or errors or cfg.send_clean_report:
        text, html = report.render(cfg, results)
        subj = report.subject(cfg, results) if results else "no containers found - check DOCKER_HOSTS"
        mailer.send(cfg, subj, text, html)
    else:
        log.info("clean scan of %d images; no email (SEND_CLEAN_REPORT=false)", len(results))
    if not errors:  # a run with errors must not satisfy the heartbeat monitor
        mailer.heartbeat(cfg)
    status = "ERRORS" if errors else ("FINDINGS" if findings else "clean")
    log.info("scan complete: %d images, %s", len(results), status)
    return 0


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="scan once and exit")
    args = ap.parse_args()
    try:
        cfg = Config.from_env()
        cfg.validate()
        if not croniter.is_valid(cfg.schedule):
            raise ValueError(f"Invalid SCHEDULE_CRON '{cfg.schedule}'")
    except Exception as e:
        log.error("configuration error: %s", e)
        return 2
    touch_health()
    if args.once:
        return run_scan(cfg)
    log.info("scheduler up: '%s', severities=%s, hosts=%s", cfg.schedule, cfg.severities,
             [h for h, _ in cfg.docker_hosts])
    if cfg.run_on_start:
        _safe_run(cfg)
    while True:
        nxt = croniter(cfg.schedule, datetime.now().astimezone()).get_next(datetime)
        log.info("next scan at %s", nxt.isoformat(timespec="minutes"))
        while datetime.now().astimezone() < nxt:
            touch_health()
            time.sleep(30)
        _safe_run(cfg)


def _safe_run(cfg: Config) -> None:
    try:
        run_scan(cfg)
    except Exception as e:
        log.exception("scan crashed")
        try:
            mailer.send(cfg, "SCANNER CRASHED", f"Unhandled error: {e}", f"<pre>Unhandled error: {e}</pre>")
        except Exception:
            log.exception("could not send crash email")
