"""Console rendering plus JSON/CSV/ TABLE serialization."""
from __future__ import annotations

import csv
import io
import json
import sys
import time

from .scanner import OPEN, TIMEOUT, UNREACHABLE, ERROR, UNKNOWN
from .util import (APP_NAME, APP_VERSION, AUTHOR, GITHUB_URL, Palette,
                   format_duration, show_logo, truncate)

SECTION_WIDTH = 60


class Reporter:
    """Human-oriented console output."""

    def __init__(self, palette: Palette, quiet: bool = False, verbose: bool = False):
        self.p = palette
        self.quiet = quiet
        self.verbose = verbose

    def rule(self):
        print("─" * SECTION_WIDTH)

    def banner(self):
        show_logo(self.p)
        print(self.p.color(f"  {APP_NAME} v{APP_VERSION}", "bold", "yellow")
              + self.p.color(f"   by {AUTHOR}", "dim")
              + self.p.color(f"  -  {GITHUB_URL}", "blue"))
        print()

    def kv(self, key, value):
        print(f"{key:<9}: {value}")

    def info(self, msg):
        if not self.quiet:
            print(msg)

    def warn(self, msg):
        print(self.p.color(f"warning: {msg}", "yellow"), file=sys.stderr)

    def error(self, msg):
        print(self.p.color(f"error: {msg}", "red"), file=sys.stderr)


class ProgressRenderer:
    """Real-time scan statistics. Renders nothing when not a TTY."""

    def __init__(self, reporter: Reporter, stats):
        self.r = reporter
        self.stats = stats
        self._tty = sys.stdout.isatty()
        self._last = 0.0
        self._prev_lines = 0

    def tick(self, current_target=""):
        now = time.monotonic()
        if now - self._last < 0.15:   # throttle redraws
            return
        self._last = now
        snap = self.stats.snapshot()
        if not self._tty:
            return  # never spam non-TTY output (piped logs stay clean)
        c = snap["counts"]
        eta = format_duration(snap["eta"]) if snap["eta"] is not None else "?"
        avg = f"{snap['avg_latency']:.0f}ms" if snap["avg_latency"] else "-"
        lines = [
            f"{APP_NAME}",
            f"Target   : {current_target}",
            f"Progress : {snap['done']} / {snap['total']}  ({snap['remaining']} remaining)",
            f"Open {c.get('OPEN', 0)}   Closed {c.get('CLOSED', 0)}   "
            f"Timeout {c.get('TIMEOUT', 0)}   Errors {c.get('ERROR', 0)}   "
            f"Unreachable {c.get('UNREACHABLE', 0)}",
            f"Speed    : {snap['rate']:.0f} ports/sec   Avg latency: {avg}",
            f"Elapsed  : {format_duration(snap['elapsed'])}   ETA: {eta}",
        ]
        if self._prev_lines:
            sys.stdout.write(f"\033[{self._prev_lines}A")  # move cursor back up
        sys.stdout.write("\r" + "\n".join("\033[2K" + ln for ln in lines))
        sys.stdout.flush()
        self._prev_lines = len(lines)

    def finish(self):
        if self._tty and self._prev_lines:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._prev_lines = 0


def _detail(res, show_evidence=False):
    """One-line detail for the results table."""
    if res.state != OPEN:
        return ""
    bits = []
    if show_evidence and res.evidence:
        bits.append(f"[{res.evidence}]")
    if res.http:
        h = res.http
        status = f"{h.get('status', '')} {h.get('reason', '')}".strip()
        bits.append(status)
        if h.get("server"):
            bits.append(h["server"])
    if res.tls.get("handshake"):
        t = res.tls
        bits.append(f"{t.get('tls_version') or 'TLS'}"
                    + (" verified" if t.get("verified") else " unverified"))
        cert = t.get("certificate") or {}
        if cert.get("not_after"):
            bits.append(f"cert expires {cert['not_after']}")
    if not bits and res.banner:
        bits.append(truncate(res.banner, 80))
    return " | ".join(bits)


def render_table(reporter: Reporter, rows, show_conf=True):
    """rows: list of PortResult. Renders the PORT/STATE/SERVICE table."""
    p = reporter.p
    if show_conf:
        header = f"{'PORT':<7}{'STATE':<14}{'SERVICE':<18}{'CONF':<8}DETAILS"
    else:
        header = f"{'PORT':<7}{'STATE':<14}{'SERVICE':<18}DETAILS"
    print(p.color(header, "bold"))
    for res in rows:
        plain_state = res.state
        padding = " " * max(1, 14 - len(plain_state))
        state = p.state(res.state)
        service = res.service or "-"
        conf = res.confidence or "-"
        detail = _detail(res, show_evidence=reporter.verbose)
        if show_conf:
            print(f"{res.port:<7}{state}{padding}{service:<18}{conf:<8}{detail}")
        else:
            print(f"{res.port:<7}{state}{padding}{service:<18}{detail}")


def render_scan(reporter: Reporter, scan_data, stats_snap, cfg, interrupted=False,
                show_closed=False):
    """Final human-readable output.

    scan_data: list of dicts {original, resolved, reverse, addresses: {ip: [PortResult]}}.
    """
    r = reporter
    counts = stats_snap["counts"]
    if not r.quiet:
        r.banner()
        for entry in scan_data:
            r.kv("Target", entry["original"])
            if entry.get("resolved"):
                r.kv("Resolved", ", ".join(entry["resolved"]))
            r.kv("Ports", entry.get("ports_desc", ""))
            r.kv("Workers", cfg.workers)
            r.kv("Timeout", f"{cfg.connect_timeout}s")
            r.rule()
            shown_states = {OPEN}
            if r.verbose or show_closed:
                shown_states |= {TIMEOUT, UNREACHABLE, ERROR, UNKNOWN}
            for addr, results in entry["addresses"].items():
                if not results:
                    continue
                if entry.get("reverse", {}).get(addr):
                    print(f"Scanning {addr} ({entry['reverse'][addr]})")
                else:
                    print(f"Scanning {addr}")
                rows = [x for x in results if x.state in shown_states]
                if rows:
                    render_table(r, sorted(rows, key=lambda x: x.port),
                                 show_conf=r.verbose)
                elif r.verbose:
                    print("  (no open ports)")
                print()
    # summary block
    r.rule()
    print(f"Open: {counts.get('OPEN', 0)}   Closed: {counts.get('CLOSED', 0)}   "
          f"Timeout: {counts.get('TIMEOUT', 0)}   Unreachable: {counts.get('UNREACHABLE', 0)}   "
          f"Errors: {counts.get('ERROR', 0)}")
    print(f"Time: {format_duration(stats_snap['elapsed'])}   "
          f"Rate: {stats_snap['rate']:.0f} ports/sec   "
          f"Scanned: {stats_snap['done']}/{stats_snap['total']}")
    if interrupted:
        r.warn("scan interrupted by user; results above are partial")


def scan_to_json(scan_data, cfg, stats_snap, warnings, started_iso):
    return {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "timestamp": started_iso,
        "configuration": {
            "workers": cfg.workers,
            "connect_timeout": cfg.connect_timeout,
            "read_timeout": cfg.read_timeout,
            "retries": cfg.retries,
            "service_detection": cfg.detect_services,
            "banner_collection": cfg.grab_banners,
            "tls_inspection": cfg.tls_inspection,
        },
        "summary": {
            "total": stats_snap["total"],
            "done": stats_snap["done"],
            "open": stats_snap["counts"].get("OPEN", 0),
            "closed": stats_snap["counts"].get("CLOSED", 0),
            "timeout": stats_snap["counts"].get("TIMEOUT", 0),
            "unreachable": stats_snap["counts"].get("UNREACHABLE", 0),
            "errors": stats_snap["counts"].get("ERROR", 0),
            "elapsed_seconds": round(stats_snap["elapsed"], 3),
            "rate_ports_per_sec": round(stats_snap["rate"], 2),
            "avg_latency_ms": round(stats_snap["avg_latency"], 2),
        },
        "warnings": list(warnings),
        "targets": [
            {
                "target": e["original"],
                "resolved_addresses": e.get("resolved", []),
                "reverse_dns": e.get("reverse", {}),
                "addresses": [
                    {"address": addr, "results": [x.to_dict() for x in results]}
                    for addr, results in e["addresses"].items()
                ],
            }
            for e in scan_data
        ],
    }


_CSV_FIELDS = [
    "host", "address", "port", "state", "service", "confidence", "evidence",
    "banner", "latency_ms", "http_status", "http_server", "http_content_type",
    "http_location", "tls_version", "tls_verified", "tls_hostname_match",
    "cert_subject", "cert_issuer", "cert_not_after",
]


def scan_to_csv(scan_data):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in scan_data:
        for addr, results in e["addresses"].items():
            for res in results:
                row = {
                    "host": e["original"], "address": addr, "port": res.port,
                    "state": res.state, "service": res.service,
                    "confidence": res.confidence, "evidence": res.evidence,
                    "banner": res.banner, "latency_ms": res.latency_ms,
                    "http_status": res.http.get("status", ""),
                    "http_server": res.http.get("server", ""),
                    "http_content_type": res.http.get("content_type", ""),
                    "http_location": res.http.get("location", ""),
                    "tls_version": res.tls.get("tls_version", ""),
                    "tls_verified": res.tls.get("verified", ""),
                    "tls_hostname_match": res.tls.get("hostname_match", ""),
                    "cert_subject": (res.tls.get("certificate") or {}).get("subject", ""),
                    "cert_issuer": (res.tls.get("certificate") or {}).get("issuer", ""),
                    "cert_not_after": (res.tls.get("certificate") or {}).get("not_after", ""),
                }
                w.writerow(row)
    return buf.getvalue()
