import logging
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from .config import Config

log = logging.getLogger("trivy-monitor")


def send(cfg: Config, subject: str, text: str, html: str) -> None:
    if cfg.dry_run:
        print(f"--- DRY RUN: would email {cfg.mail_to or '(nobody)'} ---\nSubject: {subject}\n\n{text}")
        return
    msg = EmailMessage()
    msg["Subject"] = f"{cfg.subject_prefix} {subject}"
    msg["From"] = cfg.mail_from
    msg["To"] = ", ".join(cfg.mail_to)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    if cfg.smtp_security == "ssl":
        s = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30)
    with s:
        if cfg.smtp_security == "starttls":
            s.starttls(context=ctx)
        if cfg.smtp_user:
            s.login(cfg.smtp_user, cfg.smtp_password)
        refused = s.send_message(msg)
        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")
    log.info("email sent to %s", cfg.mail_to)


def heartbeat(cfg: Config) -> None:
    if not cfg.heartbeat_url:
        return
    try:
        urllib.request.urlopen(cfg.heartbeat_url, timeout=15).read()
    except Exception as e:
        log.warning("heartbeat failed: %s", e)
