"""Interactive menu mode - uses exactly the same engines as CLI mode."""
from __future__ import annotations

import ipaddress
import time as _time

from .ports import parse_port_spec
from .targets import parse_targets, resolve_target
from .util import (APP_VERSION, AUTHOR, GITHUB_URL, InputError, box_bottom,
                   box_line, box_top, show_logo)


def _ask(prompt, default=None):
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        value = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return value or default


def _menu(palette):
    print()
    print(box_top(palette, f"HANT PORT v{APP_VERSION} - MAIN MENU"))
    items = [
        ("1", "Scan ports", "TCP port scanner"),
        ("2", "Discover hosts", "find live devices on LAN"),
        ("3", "Watch ports", "live monitoring of ports"),
        ("4", "Compare reports", "diff two saved scans"),
        ("5", "Saved reports", "view stored reports"),
        ("6", "Profiles", "scan profile reference"),
        ("7", "Config", "current configuration"),
        ("0", "Exit", "quit"),
    ]
    for num, name, desc in items:
        line = f"{palette.color(num, 'green', 'bold')}  {name:<17} {palette.color('|', 'cyan')} {palette.color(desc, 'dim')}"
        print(box_line(palette, line))
    print(box_bottom(palette))
    return palette.color("  Choice: ", "yellow", "bold")


def _mk_args(**kw):
    class Args:
        pass
    a = Args()
    defaults = dict(targets=None, ports=None, top_ports=None, profile=None,
                    workers=None, timeout=None, read_timeout=None, retries=None,
                    max_targets=None, json=False, csv=False, table=False,
                    quiet=False, verbose=False, no_color=False, no_detect=False,
                    no_banner=False, no_tls=False, output=None, no_save=False)
    defaults.update(kw)
    for k, v in defaults.items():
        setattr(a, k, v)
    return a


def _scan_flow(console, cfg):
    palette = console.p
    print()
    print(box_top(palette, "SCAN SETUP"))
    target = _ask("Target (IP / hostname / CIDR / file.txt)")
    if not target:
        print(box_bottom(palette))
        return
    try:
        parse_targets([target], cfg["max_cidr_hosts"])
    except InputError as exc:
        print(box_bottom(palette))
        console.error(str(exc))
        return
    profile = _ask("Profile (fast/common/thorough/full)", cfg["profile"])
    if profile not in ("fast", "common", "thorough", "full"):
        print(box_bottom(palette))
        console.error(f"Unknown profile '{profile}'.")
        return
    port_range = _ask("Ports (empty = profile default)", "")
    if port_range:
        try:
            parse_port_spec(port_range)
        except InputError as exc:
            print(box_bottom(palette))
            console.error(str(exc))
            return
    workers = _ask("Workers", str(cfg["workers"]))
    timeout = _ask("Timeout sec", str(cfg["connect_timeout"]))
    try:
        workers_i, timeout_f = int(workers), float(timeout)
    except (TypeError, ValueError):
        print(box_bottom(palette))
        console.error("Workers must be an integer and timeout a number.")
        return
    print(box_bottom(palette))
    print()
    print(palette.color("  Summary:", "cyan", "bold"))
    print(f"    Target  : {palette.color(target, 'white', 'bold')}")
    print(f"    Ports   : {port_range or ('profile ' + profile)}")
    print(f"    Workers : {workers_i}   Timeout: {timeout_f}s")
    try:
        confirm = input(palette.color("  Start scan? [Y/n]: ", "yellow", "bold")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        return
    if confirm in ("n", "no"):
        print("  Aborted.")
        return
    args = _mk_args(targets=[target], ports=port_range or None, profile=profile,
                    workers=workers_i, timeout=timeout_f,
                    read_timeout=cfg["read_timeout"], retries=cfg["retries"])
    from .cli import perform_scan
    perform_scan(args, cfg, console, palette, [])


def _discover_flow(console, cfg):
    palette = console.p
    print()
    print(box_top(palette, "DISCOVER SETUP"))
    net = _ask("Network CIDR (empty = auto local /24)", "")
    if net:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError as exc:
            print(box_bottom(palette))
            console.error(f"Invalid network '{net}': {exc}")
            return
    ports_s = _ask("Probe ports (empty = defaults)", "")
    if ports_s:
        try:
            ports = parse_port_spec(ports_s)
        except InputError as exc:
            print(box_bottom(palette))
            console.error(str(exc))
            return
    else:
        from .discover import DEFAULT_DISCOVERY_PORTS
        ports = list(DEFAULT_DISCOVERY_PORTS)
    w = _ask("Workers", "50")
    t = _ask("Timeout sec", "0.6")
    print(box_bottom(palette))
    try:
        w_i, t_f = int(w), float(t)
    except (TypeError, ValueError):
        console.error("Workers must be an integer and timeout a number.")
        return
    from .discover import run_discover
    run_discover(console, cfg, ports=ports, workers=w_i, timeout=t_f,
                 network=net or None)


def _watch_flow(console, cfg):
    palette = console.p
    print()
    print(box_top(palette, "WATCH SETUP"))
    target = _ask("Target (IP or hostname)")
    if not target:
        print(box_bottom(palette))
        return
    ports_s = _ask("Ports", "22,80,443")
    try:
        ports = parse_port_spec(ports_s)
    except InputError as exc:
        print(box_bottom(palette))
        console.error(str(exc))
        return
    interval = _ask("Interval sec", "10")
    timeout = _ask("Timeout sec", "1.5")
    print(box_bottom(palette))
    try:
        resolutions = []
        for t in parse_targets([target], cfg["max_cidr_hosts"]):
            r = resolve_target(t)
            if r.error:
                console.error(f"{t.original}: {r.error}")
            else:
                resolutions.append(r)
    except InputError as exc:
        console.error(str(exc))
        return
    if not resolutions:
        return
    console.banner()
    for r in resolutions:
        console.kv("Target", r.target.original)
        console.kv("Resolved", ", ".join(a for a, _ in r.addresses))
    from .watch import run_watch
    run_watch(console, resolutions, ports, float(interval), float(timeout))


def _compare_flow(console, cfg):
    from .compare import compare_reports, render_changes
    from .report import list_reports, resolve_report_path
    entries = list_reports(cfg)
    if len(entries) < 2:
        console.error("You need at least 2 saved reports. Run some scans first.")
        return
    print()
    print(box_top(console.p, "COMPARE REPORTS"))
    for i, (name, mtime, _s) in enumerate(entries[:10]):
        line = f"{console.p.color(str(i+1), 'green', 'bold')}  {_time.strftime('%m-%d %H:%M', _time.localtime(mtime))}  {name}"
        print(box_line(console.p, line))
    print(box_bottom(console.p))
    old = _ask("Old report (number or name)", "1")
    new = _ask("New report (number or name)", "2")

    def _resolve(x):
        if x and x.isdigit() and 0 < int(x) <= len(entries):
            return entries[int(x) - 1][0]
        return x

    try:
        old_p = resolve_report_path(cfg, _resolve(old))
        new_p = resolve_report_path(cfg, _resolve(new))
        render_changes(console.p, compare_reports(old_p, new_p))
    except InputError as exc:
        console.error(str(exc))


def _reports_flow(console, cfg):
    from .report import list_reports, load_report, resolve_report_path, summarize
    entries = list_reports(cfg)
    if not entries:
        print("  No saved reports yet. Run a scan first (option 1).")
        return
    print()
    print(box_top(console.p, "SAVED REPORTS"))
    for i, (name, mtime, _s) in enumerate(entries[:15]):
        line = f"{console.p.color(str(i+1), 'green', 'bold')}  {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(mtime))}  {name}"
        print(box_line(console.p, line))
    print(box_bottom(console.p))
    sel = _ask("Number or name to view (empty = cancel)", "")
    if not sel:
        return
    name = entries[int(sel) - 1][0] if sel.isdigit() and 0 < int(sel) <= len(entries) else sel
    try:
        print(summarize(load_report(resolve_report_path(cfg, name))))
    except InputError as exc:
        console.error(str(exc))


def _profiles_flow(console, cfg):
    from .ports import profile_docs, profile_ports
    p = console.p
    print()
    print(box_top(p, "SCAN PROFILES"))
    for name, desc in profile_docs().items():
        line = f"{p.color(name, 'green', 'bold'):<18} {p.color(str(len(profile_ports(name))), 'yellow'):>6} ports  {desc}"
        print(box_line(p, line))
    print(box_bottom(p))


def _config_flow(console, cfg):
    from .config import config_path
    p = console.p
    print()
    print(box_top(p, "CONFIGURATION"))
    print(box_line(p, p.color("file: ", "dim") + config_path()))
    for key in sorted(cfg):
        print(box_line(p, f"{p.color(key, 'cyan'):<20}: {cfg[key]}"))
    print(box_bottom(p))


_FLOWS = {
    "1": _scan_flow, "2": _discover_flow, "3": _watch_flow, "4": _compare_flow,
    "5": _reports_flow, "6": _profiles_flow, "7": _config_flow,
}


def run_interactive(console, cfg):
    palette = console.p
    show_logo(palette, "TCP Port Scanner - no root required")
    print(palette.color(f"  v{APP_VERSION}", "bold", "yellow"))
    print(palette.color("  Interactive mode - same real engines as the CLI", "dim"))
    print(palette.color(f"  by {AUTHOR}  -  {GITHUB_URL}", "blue", "dim"))
    while True:
        prompt = _menu(palette)
        try:
            choice = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye!")
            return 0
        if choice == "0":
            print("  Bye!")
            return 0
        flow = _FLOWS.get(choice)
        if flow is None:
            console.error("Invalid choice - enter a number from the menu.")
            continue
        try:
            flow(console, cfg)
        except KeyboardInterrupt:
            print("\n  (interrupted)")
        except Exception as exc:
            console.error(f"unexpected error: {exc}")
