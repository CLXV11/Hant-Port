"""Scan report persistence and display."""
from __future__ import annotations

import json
import os
import pathlib
import time

from .util import InputError, format_duration


def reports_dir(cfg) -> str:
    d = os.path.expanduser(cfg.get("output_dir") or "~/.hantport/reports")
    os.makedirs(d, exist_ok=True)
    return d


def save_report(data: dict, cfg) -> str:
    d = reports_dir(cfg)
    name = "scan-" + time.strftime("%Y%m%d-%H%M%S") + ".json"
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def list_reports(cfg):
    d = reports_dir(cfg)
    entries = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            st = os.stat(os.path.join(d, name))
            entries.append((name, st.st_mtime, st.st_size))
    entries.sort(key=lambda x: -x[1])
    return entries


def latest_report_path(cfg):
    entries = list_reports(cfg)
    if not entries:
        return None
    return os.path.join(reports_dir(cfg), entries[0][0])


def resolve_report_path(cfg, name):
    if name in (None, "", "latest"):
        path = latest_report_path(cfg)
        if not path:
            raise InputError("No saved reports yet. Run a scan first (reports are saved automatically).")
        return path
    d = reports_dir(cfg)
    for candidate in (name, name + ".json"):
        path = os.path.join(d, candidate)
        if os.path.isfile(path):
            return path
    raise InputError(f"Report '{name}' not found in {d}.")


def load_report(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise InputError(f"Report file '{path}' is corrupted or not valid JSON: "
                         f"{exc.msg} (line {exc.lineno}, column {exc.colno}).")
    except OSError as exc:
        raise InputError(f"Cannot read report '{path}': {exc}.")
    if not isinstance(data, dict) or "targets" not in data:
        raise InputError(f"File '{path}' is not a HANT PORT scan report.")
    return data


def summarize(data: dict):
    """Human-readable summary of a report dict."""
    s = data.get("summary", {})
    lines = []
    lines.append(f"{data.get('tool', 'HANT PORT')} report  {data.get('timestamp', '')}")
    lines.append(f"duration: {format_duration(s.get('elapsed_seconds', 0))}"
                 f"   rate: {s.get('rate_ports_per_sec', 0)} ports/sec")
    lines.append(f"ports: done {s.get('done', 0)}/{s.get('total', 0)}"
                 f"   open {s.get('open', 0)}   closed {s.get('closed', 0)}"
                 f"   timeout {s.get('timeout', 0)}   unreachable {s.get('unreachable', 0)}"
                 f"   errors {s.get('errors', 0)}")
    for t in data.get("targets", []):
        lines.append("")
        lines.append(f"target: {t.get('target')}")
        resolved = t.get("resolved_addresses") or []
        if resolved:
            lines.append(f"  resolved: {', '.join(resolved)}")
        for addr_entry in t.get("addresses", []):
            addr = addr_entry.get("address")
            opens = [r for r in addr_entry.get("results", []) if r.get("state") == "OPEN"]
            if not opens:
                lines.append(f"  {addr}: no open ports")
                continue
            lines.append(f"  {addr}: {len(opens)} open port(s)")
            for r in opens:
                svc = r.get("service") or "-"
                conf = r.get("confidence") or "-"
                banner = (r.get("banner") or "").strip()
                extra = f"   [{banner[:70]}]" if banner else ""
                lines.append(f"    {r.get('port')}/tcp OPEN  {svc} ({conf}){extra}")
    return "\n".join(lines)
