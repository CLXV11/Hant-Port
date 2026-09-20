"""Compare two scan reports and report factual changes only."""
from __future__ import annotations

from .report import load_report
from .util import InputError


def _index(data: dict):
    """Flatten a report into {(address, port): result_dict}."""
    idx = {}
    for t in data.get("targets", []):
        for addr_entry in t.get("addresses", []):
            addr = addr_entry.get("address")
            for r in addr_entry.get("results", []):
                idx[(addr, r.get("port"))] = r
    return idx


def _cert_key(res: dict):
    cert = res.get("tls", {}).get("certificate") or {}
    return (cert.get("sha256") or "", cert.get("not_after") or "",
            cert.get("subject") or "")


def compare_reports(old_path: str, new_path: str):
    """Returns a list of change strings (already prefixed with +/-/~)."""
    old = _index(load_report(old_path))
    new = _index(load_report(new_path))
    changes = []
    for key in sorted(set(old) | set(new), key=lambda k: (k[0] or "", k[1] or 0)):
        addr, port = key
        o, n = old.get(key), new.get(key)
        o_open = bool(o and o.get("state") == "OPEN")
        n_open = bool(n and n.get("state") == "OPEN")
        label = f"{port}/tcp"
        if n_open and not o_open:
            svc = n.get("service") or "unknown"
            changes.append(("NEW_OPEN", f"+ {label} OPEN on {addr} ({svc})"))
        elif o_open and not n_open:
            svc = o.get("service") or "unknown"
            new_state = n.get("state") if n else "not scanned"
            changes.append(("PORT_CLOSED", f"- {label} on {addr} (was OPEN: {svc}; now: {new_state})"))
        elif o_open and n_open:
            o_svc = (o.get("service") or "").lower()
            n_svc = (n.get("service") or "").lower()
            if o_svc and n_svc and o_svc != n_svc:
                changes.append(("SERVICE_CHANGED",
                                f"~ {label} on {addr} service changed: {o.get('service')} -> {n.get('service')}"))
            o_banner = (o.get("banner") or "").strip()
            n_banner = (n.get("banner") or "").strip()
            if o_banner and n_banner and o_banner != n_banner:
                changes.append(("BANNER_CHANGED",
                                f"~ {label} on {addr} banner changed:"
                                f"\n    old: {o_banner[:90]}\n    new: {n_banner[:90]}"))
            if _cert_key(o) != _cert_key(n) and (o.get("tls") or n.get("tls")):
                cert = (n.get("tls") or {}).get("certificate") or {}
                expiry = f", new cert expires {cert['not_after']}" if cert.get("not_after") else ""
                changes.append(("CERT_CHANGED", f"~ {label} on {addr} TLS certificate changed{expiry}"))
    return changes


def render_changes(palette, changes):
    counts = {}
    lines = []
    for kind, text in changes:
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "NEW_OPEN":
            lines.append(palette.color(text, "green", "bold"))
        elif kind == "PORT_CLOSED":
            lines.append(palette.color(text, "red"))
        else:
            lines.append(palette.color(text, "yellow"))
    print(palette.color("CHANGES", "bold"))
    print("─" * 40)
    if not lines:
        print("No changes detected.")
    else:
        for line in lines:
            print(line)
    print("─" * 40)
    print(f"total: {len(changes)} change(s)  "
          f"(new open: {counts.get('NEW_OPEN', 0)}, closed: {counts.get('PORT_CLOSED', 0)}, "
          f"service/banner/cert: {sum(v for k, v in counts.items() if k not in ('NEW_OPEN', 'PORT_CLOSED'))})")
