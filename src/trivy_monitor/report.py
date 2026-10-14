import html
from datetime import datetime

from . import clock
from .config import Config
from .scanner import ImageResult, human_age, recommend

SEV_COLOUR = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#558b2f", "UNKNOWN": "#757575"}


def summary_counts(results: list[ImageResult]) -> dict[str, int]:
    c: dict[str, int] = {}
    for r in results:
        for v, _ in r.by_cve():
            c[v.severity] = c.get(v.severity, 0) + 1
    return c


def subject(cfg: Config, results: list[ImageResult]) -> str:
    bad = [r for r in results if r.vulns]
    errs = [r for r in results if r.error]
    sev = summary_counts(results)
    parts = [f"{n} {s}" for s, n in sorted(sev.items(), key=lambda x: -len(x[0])) if n]
    new = sum(len(r.new_keys) for r in results)
    base = f"{len(bad)} image(s) vulnerable ({', '.join(parts)})" if bad else "all clear"
    if new:
        base += f", {new} new"
    if errs:
        base += f", {len(errs)} scan error(s)"
    name = f"{cfg.instance_name} " if cfg.instance_name else ""
    return name + base


def render(cfg: Config, results: list[ImageResult], max_rows: int | None = -1,
           notes: list[str] | None = None) -> tuple[str, str]:
    """max_rows: -1 = cfg.max_cves_per_image (email), None = every CVE (archive copy)."""
    if max_rows == -1:
        max_rows = cfg.max_cves_per_image
    bad = [r for r in results if r.vulns]
    errs = [r for r in results if r.error]
    t, h = [], []
    now = clock.now().strftime("%Y-%m-%d %H:%M %Z")
    t.append(f"Trivy scan {now}: {len(results)} images, severities {','.join(cfg.severities)}"
             f"{', fixable only' if cfg.only_fixable else ''}")
    h.append(f"<h2>Trivy CVE report</h2><p>{now} &middot; {len(results)} images &middot; "
             f"severities: {html.escape(','.join(cfg.severities))}</p>")
    for n in notes or []:
        t += ["", f"NOTE: {n}"]
        h.append(f"<p><b>Note:</b> {html.escape(n)}</p>")
    stacks: dict[str, list[int]] = {}
    for r in bad:
        for st in r.stacks or ["?"]:
            row = stacks.setdefault(st, [0, 0])
            row[0] += sum(v.severity == "CRITICAL" for v, _ in r.by_cve())
            row[1] += sum(v.severity == "HIGH" for v, _ in r.by_cve())
    if stacks:
        t += ["", "BY STACK (critical / high, summed over its images):"]
        h.append("<h3>By stack</h3><table cellpadding=4><tr><th align=left>Stack</th><th>Critical</th><th>High</th></tr>")
        for st, (c, hi) in sorted(stacks.items(), key=lambda x: (-x[1][0], -x[1][1])):
            t.append(f"  {st:30} {c:5} / {hi}")
            h.append(f"<tr><td>{html.escape(st)}</td><td align=right>{c}</td><td align=right>{hi}</td></tr>")
        h.append("</table>")
    bad.sort(key=lambda r: (-sum(v.severity == 'CRITICAL' for v, _ in r.by_cve()), -r.cve_count))
    for r in bad:
        sevc = {}
        for v, _ in r.by_cve():
            sevc[v.severity] = sevc.get(v.severity, 0) + 1
        sevtxt = ", ".join(f"{n} {s}" for s, n in sevc.items())
        warn = "  [HIGH BLAST RADIUS]" if r.caution else ""
        age = f"; oldest CVE published {human_age(r.oldest_cve_days)} ago, {r.old_cves} older than a year" if r.oldest_cve_days is not None else ""
        t += ["", f"== {r.ref} @ {r.host}{warn}", f"   stack: {', '.join(r.stacks) or '?'}   containers: {', '.join(sorted(r.containers))}",
              f"   {sevtxt}; {r.fixable} have a fixed package version; {len({k.split('|')[0] for k in r.new_keys})} new since last run{age}"]
        h.append(f"<h3>{html.escape(r.ref)} <small>@ {html.escape(r.host)}</small>"
                 f"{' <span style=color:#b71c1c>&#9888; high blast radius</span>' if r.caution else ''}</h3>"
                 f"<p>Stack: <b>{html.escape(', '.join(r.stacks) or '?')}</b> &middot; containers: {html.escape(', '.join(sorted(r.containers)))}<br>{html.escape(sevtxt)}{html.escape(age)} "
                 f"&middot; {r.fixable} with a fixed package version &middot; {len({k.split('|')[0] for k in r.new_keys})} new CVEs</p>")
        rec = recommend(r)
        t.append(f"   RECOMMENDATION: {rec}")
        h.append(f"<p><b>Recommendation:</b> {html.escape(rec)}</p>")
        ups = [u for u in r.upstream if not u.error]
        if ups:
            t.append("   Upstream options:")
            h.append("<ul>")
            for u in ups:
                line = f"{u.label}: clears {u.cleared}, {u.remaining} remain"
                t.append(f"     - {line}")
                h.append(f"<li>{html.escape(line)}</li>")
            h.append("</ul>")
        for a in r.alternatives:
            line = (f"alternative {a.ref}: " + (f"error {a.error}" if a.error else
                    f"published {human_age(a.last_published_days)} ago, {a.critical} critical / {a.high} high"))
            t.append(f"   {line}")
            h.append(f"<p>&#8594; {html.escape(line)}</p>")
        for u in (u for u in r.upstream if u.error):
            t.append(f"   (note: {u.label}: {u.error})")
        rows = r.by_cve()
        shown = rows if max_rows is None else rows[:max_rows]
        h.append("<table cellpadding=4 style='border-collapse:collapse;font-size:13px'>"
                 "<tr><th align=left>Sev</th><th align=left>CVE</th><th align=left>Package</th>"
                 "<th align=left>Installed</th><th align=left>Fixed in</th><th align=left>Age</th></tr>")
        for v, pkgs in shown:
            pk = pkgs[0] + (f" (+{len(set(pkgs)) - 1} more)" if len(set(pkgs)) > 1 else "")
            col = SEV_COLOUR.get(v.severity, "#000")
            mark = "NEW " if any(k.startswith(v.id + "|") for k in r.new_keys) else ""
            t.append(f"     {v.severity:8} {mark}{v.id}  {pk} {v.installed} -> {v.fixed or 'no fix yet'}  (published {human_age(v.age_days)} ago)")
            link = f"<a href='{html.escape(v.url)}'>{html.escape(v.id)}</a>" if v.url else html.escape(v.id)
            h.append(f"<tr><td style='color:{col}'><b>{v.severity}</b></td><td>{mark and '<b>NEW</b> '}{link}</td>"
                     f"<td>{html.escape(pk)}</td><td>{html.escape(v.installed)}</td>"
                     f"<td>{html.escape(v.fixed) or '<i>no fix yet</i>'}</td><td>{human_age(v.age_days)}</td></tr>")
        h.append("</table>")
        if len(rows) > len(shown):
            t.append(f"     ... and {len(rows) - len(shown)} more CVEs")
            h.append(f"<p>&hellip; and {len(rows) - len(shown)} more CVEs</p>")
    if errs:
        t += ["", "SCAN ERRORS (these images were NOT verified):"]
        h.append("<h3 style=color:#b71c1c>Scan errors - not verified</h3><ul>")
        for r in errs:
            t.append(f"  - {r.ref} @ {r.host}: {r.error}")
            h.append(f"<li>{html.escape(r.ref)} @ {html.escape(r.host)}: {html.escape(r.error)}</li>")
        h.append("</ul>")
    if not bad and not errs:
        t.append("\nNo findings at the configured severities.")
        h.append("<p>No findings at the configured severities.</p>")
    return "\n".join(t), "<html><body style='font-family:sans-serif'>" + "".join(h) + "</body></html>"
