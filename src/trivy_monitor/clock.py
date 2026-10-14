"""Timezone handling that works without OS tzdata (the runtime image is distroless): uses the tzdata wheel."""
import logging
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger("trivy-monitor")


def _load() -> tuple[object, str]:
    name = os.environ.get("TZ", "").strip() or "UTC"
    try:
        return ZoneInfo(name), ""
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc, f"unknown TZ '{name}', falling back to UTC (schedule and timestamps will be UTC)"


TZ, TZ_WARNING = _load()


def now() -> datetime:
    return datetime.now(TZ)


def install_log_timezone() -> None:
    logging.Formatter.converter = staticmethod(lambda ts: datetime.fromtimestamp(ts, TZ).timetuple())
    if TZ_WARNING:
        log.warning(TZ_WARNING)
