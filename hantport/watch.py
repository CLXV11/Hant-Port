"""Live monitoring of selected ports with transition detection."""
from __future__ import annotations

import datetime
import threading

from .scanner import probe_port_state
from .util import format_duration


def run_watch(console, resolutions, ports, interval, timeout, quiet=False):
    stop = threading.Event()

    def _ts():
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    console.info(f"Monitoring {len(resolutions)} target(s), ports "
                 f"{','.join(str(p) for p in ports)} every {interval}s (Ctrl+C to stop)")
    prev = {}
    exit_code = 0
    try:
        while not stop.is_set():
            events = []
            for res in resolutions:
                for addr, _ver in res.addresses:
                    for port in ports:
                        state = probe_port_state(addr, port, timeout)
                        key = (addr, port)
                        if key not in prev:
                            if not quiet:
                                events.append(f"{addr}:{port} initial state: {state}")
                        elif prev[key] != state:
                            events.append(f"{addr}:{port} {prev[key]} -> {state}")
                        prev[key] = state
            for ev in events:
                print(f"[{_ts()}] {ev}")
            stop.wait(interval)
    except KeyboardInterrupt:
        print(f"\n[{_ts()}] monitoring stopped by user (Ctrl+C)")
    return exit_code
