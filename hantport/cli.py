"""Command-line interface for HANT PORT."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time

from . import APP_NAME, APP_VERSION
from .compare import compare_reports, render_changes
from .config import config_path, load_config
from .discover import DEFAULT_DISCOVERY_PORTS, run_discover
from .output import ProgressRenderer, Reporter, render_scan, scan_to_csv, scan_to_json
from .ports import parse_port_spec, profile_docs, profile_ports, top_ports
from .report import (list_reports, load_report, resolve_report_path,
                     save_report, summarize)
from .scanner import ScanConfig, ScanEngine, ScanStats
from .targets import load_targets_file, parse_targets, resolve_target
from .util import AUTHOR, GITHUB_URL, InputError, Palette


def build_parser():
    p = argparse.ArgumentParser(
        prog="hant",
        description=f"{APP_NAME} v{APP_VERSION} - TCP port scanner for Termux (no root required)",
    )
    p.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}  |  by {AUTHOR}  -  {GITHUB_URL}")
    p.add_argument("--config", help="Path to an alternate configuration file")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="Scan targets (default command options shown via 'hant scan -h')")
    sp.add_argument("targets", nargs="+",
                    help="IPs, hostnames, CIDR ranges, and/or .txt target files")
    sp.add_argument("-p", "--ports", help="Ports: 80 | 1-1024 | 22,80,443 | 1-100,8080")
    sp.add_argument("--top-ports", type=int, metavar="N", help="Scan the N most common ports")
    sp.add_argument("--profile", choices=["fast", "common", "thorough", "full", "custom"],
                    help="Scan profile (default: config or 'common')")
    sp.add_argument("--workers", type=int, help="Concurrent connections, 1-1024 (default 100)")
    sp.add_argument("--timeout", type=float, help="Connect timeout in seconds (default 1.0)")
    sp.add_argument("--read-timeout", type=float, help="Banner/protocol read timeout (default 1.5)")
    sp.add_argument("--retries", type=int, help="Retries for timeout/error results (default 1)")
    sp.add_argument("--max-targets", type=int, help="Max hosts a CIDR may expand to (default 4096)")
    mode = sp.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    mode.add_argument("--csv", action="store_true", help="CSV output")
    mode.add_argument("--table", action="store_true", help="Force plain table output (default)")
    lvl = sp.add_mutually_exclusive_group()
    lvl.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    lvl.add_argument("-v", "--verbose", action="store_true",
                     help="Show all port states and evidence details")
    sp.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    sp.add_argument("--no-detect", action="store_true", help="Disable service detection")
    sp.add_argument("--no-banner", action="store_true", help="Disable banner collection")
    sp.add_argument("--no-tls", action="store_true", help="Disable TLS inspection")
    sp.add_argument("-o", "--output", help="Also write the report JSON to this path")
    sp.add_argument("--no-save", action="store_true", help="Do not save report to the report directory")

    wp = sub.add_parser("watch", help="Monitor ports continuously, report state transitions")
    wp.add_argument("targets", nargs="+", help="IPs, hostnames, or CIDR ranges")
    wp.add_argument("--ports", default="22,80,443", help="Ports to watch (default 22,80,443)")
    wp.add_argument("--interval", type=float, default=10.0, help="Seconds between checks (default 10)")
    wp.add_argument("--timeout", type=float, default=1.5, help="Connect timeout (default 1.5)")
    wp.add_argument("--no-color", action="store_true")

    cp = sub.add_parser("compare", help="Compare two scan reports")
    cp.add_argument("old", help="Older report JSON (or name in report directory)")
    cp.add_argument("new", help="Newer report JSON (or name in report directory)")
    cp.add_argument("--no-color", action="store_true")

    rp = sub.add_parser("report", help="Show saved scan reports")
    rp.add_argument("name", nargs="?", default="latest",
                    help="'list', 'latest', or a report file name (default: latest)")
    rp.add_argument("--no-color", action="store_true")

    dp = sub.add_parser("discover", help="Find live hosts on the local network (no root)")
    dp.add_argument("--ports", help="Probe ports (default: common service ports)")
    dp.add_argument("--workers", type=int, default=50)
    dp.add_argument("--timeout", type=float, default=0.6)
    dp.add_argument("--network", help="CIDR to scan instead of auto-detected local /24")
    dp.add_argument("--no-color", action="store_true")

    sub.add_parser("profiles", help="Show scan profiles and the ports they cover")
    sub.add_parser("config", help="Show the effective configuration")
    return p


def _collect_targets(args, cfg, warnings):
    max_cidr = getattr(args, "max_targets", None) or cfg["max_cidr_hosts"]
    targets, seen = [], set()
    for spec in args.targets:
        if os.path.isfile(spec):
            loaded, invalid = load_targets_file(spec, max_cidr)
            for lineno, text, err in invalid:
                warnings.append(f"{spec}:{lineno}: invalid line ignored: '{text}' ({err})")
            if not loaded:
                warnings.append(f"Target file '{spec}' contained no valid targets.")
        else:
            if (os.sep in spec or spec.lower().endswith(".txt")) and not os.path.exists(spec):
                raise InputError(f"Target file '{spec}' does not exist.")
            try:
                loaded = parse_targets([spec], max_cidr)
            except InputError as exc:
                raise InputError(f"Invalid target '{spec}': {exc}")
        for t in loaded:
            if t.original not in seen:
                seen.add(t.original)
                targets.append(t)
    if not targets:
        raise InputError("No valid targets to scan.")
    return targets


def _resolve_all(targets, warnings):
    resolutions = []
    for t in targets:
        r = resolve_target(t)
        if r.error:
            warnings.append(f"{t.original}: {r.error}")
        else:
            resolutions.append(r)
    if not resolutions:
        raise InputError("None of the targets could be resolved. "
                         "Check DNS, network connectivity, or airplane mode.")
    return resolutions


def _resolve_ports(args, cfg):
    if getattr(args, "ports", None):
        return parse_port_spec(args.ports), args.ports
    if getattr(args, "top_ports", None):
        return top_ports(args.top_ports), f"top {args.top_ports} ports"
    profile = getattr(args, "profile", None) or cfg["profile"]
    if profile == "custom":
        raise InputError("--profile custom requires an explicit port list (-p PORTS).")
    ports = profile_ports(profile)
    return ports, f"profile '{profile}' ({len(ports)} ports: {profile_docs()[profile]})"


def perform_scan(args, cfg, console, palette, warnings):
    scfg = ScanConfig(
        workers=getattr(args, "workers", None) or cfg["workers"],
        connect_timeout=getattr(args, "timeout", None) or cfg["connect_timeout"],
        read_timeout=getattr(args, "read_timeout", None) or cfg["read_timeout"],
        retries=cfg["retries"] if getattr(args, "retries", None) is None else args.retries,
        detect_services=not getattr(args, "no_detect", False) and cfg["service_detection"],
        grab_banners=not getattr(args, "no_banner", False) and cfg["banner"],
        tls_inspection=not getattr(args, "no_tls", False) and cfg["tls_inspection"],
    )

    # File-descriptor guard: never ask the OS for more sockets than it can give.
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need = scfg.workers * 3 + 32
        if need > soft:
            reduced = max(16, (soft - 32) // 3)
            warnings.append(f"File descriptor limit is {soft}; reduced workers from "
                            f"{scfg.workers} to {reduced}. Raise with: ulimit -n 4096")
            scfg.workers = reduced
    except Exception:
        pass

    n_prior = len(warnings)
    targets = _collect_targets(args, cfg, warnings)
    resolutions = _resolve_all(targets, warnings)
    for w in warnings[n_prior:]:          # surface target/resolve issues live
        console.warn(w)
    ports, ports_desc = _resolve_ports(args, cfg)

    total = sum(len(r.addresses) for r in resolutions) * len(ports)
    stats = ScanStats(total)
    engine = ScanEngine(scfg)

    scan_data, addr_map = [], {}
    for r in resolutions:
        entry = {
            "original": r.target.original,
            "resolved": [a for a, _v in r.addresses],
            "reverse": r.reverse,
            "addresses": {a: [] for a, _v in r.addresses},
            "ports_desc": ports_desc,
        }
        scan_data.append(entry)
        for a, _v in r.addresses:
            addr_map[(r.target.original, a)] = entry["addresses"][a]

    machine = bool(getattr(args, "json", False) or getattr(args, "csv", False))
    quiet = bool(getattr(args, "quiet", False))
    verbose = bool(getattr(args, "verbose", False))
    console.quiet = quiet
    console.verbose = verbose
    progress = ProgressRenderer(console, stats) if (not machine and not quiet) else None

    label = {"t": ""}
    interrupted = {"flag": False}

    def on_result(res):
        stats.add(res)
        label["t"] = res.host
        addr_map[(res.host, res.address)].append(res)

    def on_warning(msg):
        warnings.append(msg)
        console.warn(msg)

    def on_tick():
        if progress:
            progress.tick(label["t"])

    started_iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    work = (
        (r.target.original, addr, port,
         (r.target.original if r.target.is_hostname else None))
        for r in resolutions
        for addr, _v in r.addresses
        for port in ports
    )
    try:
        engine.run(work, on_result, on_tick=on_tick, on_warning=on_warning)
    except KeyboardInterrupt:
        interrupted["flag"] = True
        engine.request_stop()
    finally:
        if progress:
            progress.finish()

    snap = stats.snapshot()
    data = scan_to_json(scan_data, scfg, snap, warnings, started_iso)

    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    elif getattr(args, "csv", False):
        sys.stdout.write(scan_to_csv(scan_data))
    else:
        render_scan(console, scan_data, snap, scfg, interrupted=interrupted["flag"])

    if not getattr(args, "no_save", False) or getattr(args, "output", None):
        try:
            if getattr(args, "output", None):
                out_path = os.path.expanduser(args.output)
                with open(out_path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                (print if not machine else lambda m: print(m, file=sys.stderr))(f"Report saved: {out_path}")
            if not getattr(args, "no_save", False):
                path = save_report(data, cfg)
                if machine or quiet:
                    print(f"Report saved: {path}", file=sys.stderr)
                else:
                    console.info(f"Report saved: {path}")
        except OSError as exc:
            console.warn(f"could not save report: {exc}")

    return 130 if interrupted["flag"] else 0


def _resolve_for_watch(args, cfg, console):
    targets = _collect_targets(args, cfg, [])
    resolutions = _resolve_all(targets, [])
    return resolutions


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg, warnings = load_config(getattr(args, "config", None))
    colors = cfg["colors"] and not os.environ.get("NO_COLOR")
    if getattr(args, "no_color", False):
        colors = False
    palette = Palette(colors)
    console = Reporter(palette,
                       quiet=getattr(args, "quiet", False),
                       verbose=getattr(args, "verbose", False))
    for w in warnings:
        console.warn(w)

    if not args.command:
        from .interactive import run_interactive
        return run_interactive(console, cfg)

    try:
        if args.command == "scan":
            return perform_scan(args, cfg, console, palette, warnings)

        if args.command == "watch":
            ports = parse_port_spec(args.ports)
            resolutions = _resolve_for_watch(args, cfg, console)
            console.banner()
            for r in resolutions:
                console.kv("Target", r.target.original)
                console.kv("Resolved", ", ".join(a for a, _ in r.addresses))
            console.rule()
            from .watch import run_watch
            return run_watch(console, resolutions, ports, args.interval, args.timeout)

        if args.command == "compare":
            old = resolve_report_path(cfg, args.old) if not os.path.isfile(args.old) else args.old
            new = resolve_report_path(cfg, args.new) if not os.path.isfile(args.new) else args.new
            changes = compare_reports(old, new)
            render_changes(palette, changes)
            return 0

        if args.command == "report":
            if args.name == "list":
                entries = list_reports(cfg)
                if not entries:
                    print("No saved reports yet.")
                    return 0
                for name, mtime, size in entries:
                    print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}  "
                          f"{size:>8} bytes  {name}")
                return 0
            path = resolve_report_path(cfg, args.name)
            print(summarize(load_report(path)))
            return 0

        if args.command == "discover":
            ports = parse_port_spec(args.ports) if args.ports else list(DEFAULT_DISCOVERY_PORTS)
            return run_discover(console, cfg, ports=ports, workers=args.workers,
                                timeout=args.timeout, network=args.network)

        if args.command == "profiles":
            print(f"{APP_NAME} scan profiles")
            print("─" * 50)
            for name, desc in profile_docs().items():
                print(f"{name:<10} {desc}")
            print("\nfast:      " + str(len(profile_ports("fast"))) + " ports")
            print("common:    " + str(len(profile_ports("common"))) + " ports")
            print("thorough:  " + str(len(profile_ports("thorough"))) + " ports")
            print("full:      " + str(len(profile_ports("full"))) + " ports")
            print("\ncustom:    define exactly with -p (e.g. -p 22,80,443 or -p 1-1024)")
            return 0

        if args.command == "config":
            print(f"{APP_NAME} v{APP_VERSION}  by {AUTHOR}")
            print(f"GitHub: {GITHUB_URL}")
            print(f"Configuration file: {config_path()}")
            print("─" * 50)
            for key in sorted(cfg):
                print(f"{key:<18}: {cfg[key]}")
            return 0

    except InputError as exc:
        console.error(str(exc))
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
