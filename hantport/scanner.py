"""Real TCP connect-scanning engine with bounded concurrency.

States are distinguished honestly:
  OPEN        - remote host accepted the TCP connection
  CLOSED      - host reachable, port closed (RST received)
  TIMEOUT     - no answer within the timeout (silently dropped / filtered)
  UNREACHABLE - OS reported host/network unreachable (ICMP error)
  ERROR       - other OS-level error (e.g. permission denied)
  UNKNOWN     - state could not be determined
"""
from __future__ import annotations

import errno
import socket
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, asdict

from .ports import port_hint
from .service import inspect_service

OPEN = "OPEN"
CLOSED = "CLOSED"
TIMEOUT = "TIMEOUT"
UNREACHABLE = "UNREACHABLE"
ERROR = "ERROR"
UNKNOWN = "UNKNOWN"

ALL_STATES = (OPEN, CLOSED, TIMEOUT, UNREACHABLE, ERROR, UNKNOWN)

STATE_REASONS = {
    OPEN: "TCP connection accepted by the remote host",
    CLOSED: "connection refused: host is reachable and the port is closed (RST received)",
    TIMEOUT: "no response within the timeout: packets may be filtered by a firewall or silently dropped",
    UNREACHABLE: "the operating system reported the host or network as unreachable",
    ERROR: "the operating system reported an error",
    UNKNOWN: "the port state could not be determined",
}


@dataclass
class ScanConfig:
    workers: int = 100
    connect_timeout: float = 1.0
    read_timeout: float = 1.5
    retries: int = 1
    detect_services: bool = True
    grab_banners: bool = True
    tls_inspection: bool = True
    inflight_multiplier: int = 3  # bounded-queue depth per worker (backpressure)


@dataclass
class PortResult:
    host: str          # original target (hostname/IP/CIDR as typed)
    address: str       # concrete IP actually scanned
    port: int
    state: str
    reason: str = ""
    service: str = ""
    confidence: str = ""     # HIGH / MEDIUM / LOW / ""
    evidence: str = ""
    banner: str = ""
    latency_ms: float = 0.0
    http: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class ScanStats:
    """Thread-safe live statistics."""

    def __init__(self, total: int):
        self._lock = threading.Lock()
        self.total = total
        self.done = 0
        self.counts = {s: 0 for s in ALL_STATES}
        self.latency_sum = 0.0
        self.latency_n = 0
        self.start = time.monotonic()

    def add(self, result: PortResult):
        with self._lock:
            self.done += 1
            self.counts[result.state] = self.counts.get(result.state, 0) + 1
            if result.latency_ms:
                self.latency_sum += result.latency_ms
                self.latency_n += 1

    def snapshot(self):
        with self._lock:
            elapsed = max(time.monotonic() - self.start, 1e-9)
            rate = self.done / elapsed
            remaining = max(self.total - self.done, 0)
            return {
                "total": self.total, "done": self.done, "remaining": remaining,
                "counts": dict(self.counts),
                "elapsed": elapsed, "rate": rate,
                "eta": (remaining / rate) if rate > 0 else None,
                "avg_latency": (self.latency_sum / self.latency_n) if self.latency_n else 0.0,
            }


class ScanEngine:
    """TCP connect scanner. Bounded in-flight tasks provide backpressure."""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self._emfile = threading.Event()
        self._emfile_lock = threading.Lock()
        self._emfile_count = 0

    def request_stop(self):
        """Ask the engine to stop submitting new work (running tasks finish)."""
        self.stop_event.set()

    def scan_port(self, host_label, address, port, server_hostname=None) -> PortResult:
        attempts = max(1, self.cfg.retries + 1)
        last_state, last_reason = UNKNOWN, STATE_REASONS[UNKNOWN]
        for _attempt in range(attempts):
            t0 = time.monotonic()
            try:
                sock = socket.create_connection((address, port), timeout=self.cfg.connect_timeout)
            except ConnectionRefusedError:
                return PortResult(host_label, address, port, CLOSED, STATE_REASONS[CLOSED])
            except (socket.timeout, TimeoutError):
                last_state, last_reason = TIMEOUT, STATE_REASONS[TIMEOUT]
                continue
            except OSError as exc:
                code = exc.errno
                if code == errno.EHOSTUNREACH:
                    return PortResult(host_label, address, port, UNREACHABLE, STATE_REASONS[UNREACHABLE])
                if code == errno.ENETUNREACH:
                    return PortResult(host_label, address, port, UNREACHABLE,
                                      "network unreachable: no route (IPv6 may be unavailable on this device)")
                if code in (errno.EACCES, errno.EPERM):
                    return PortResult(host_label, address, port, ERROR,
                                      f"permission denied by the operating system: {exc.strerror or exc}")
                if code in (errno.EMFILE, errno.ENFILE):
                    with self._emfile_lock:
                        self._emfile_count += 1
                    self._emfile.set()
                    last_state = ERROR
                    last_reason = ("too many open files (OS socket limit reached); "
                                   "reduce --workers or raise the limit with 'ulimit -n'")
                    time.sleep(0.05)
                    continue
                if code == errno.EAFNOSUPPORT:
                    return PortResult(host_label, address, port, ERROR,
                                      "address family not supported by this runtime (IPv6 unsupported?)")
                last_state, last_reason = ERROR, f"{exc.strerror or exc}"
                continue
            latency = (time.monotonic() - t0) * 1000.0
            res = PortResult(host_label, address, port, OPEN, STATE_REASONS[OPEN],
                             latency_ms=round(latency, 2))
            if self.cfg.detect_services:
                try:
                    inspect_service(sock, address, port, server_hostname, res, self.cfg)
                except Exception as exc:  # detection must never break a scan
                    res.evidence = res.evidence or f"service detection error: {exc}"
                finally:
                    try:
                        sock.close()
                    except OSError:
                        pass
            else:
                try:
                    sock.close()
                except OSError:
                    pass
                hint = port_hint(port)
                if hint:
                    res.service, res.confidence, res.evidence = \
                        hint[0], "LOW", "service detection disabled; port-number association only"
            return res
        return PortResult(host_label, address, port, last_state, last_reason)

    def run(self, work, on_result, on_tick=None, on_warning=None):
        """Run the scan.

        work: iterable of (host_label, address, port, server_hostname).
        on_result: callable(PortResult) - invoked from the main thread.
        on_tick: optional callable() - called periodically with progress.
        on_warning: optional callable(str) - engine warnings (e.g. EMFILE).

        Concurrency is bounded: at most workers * inflight_multiplier tasks
        are in flight, which bounds memory and socket usage regardless of
        how large the target/port space is.
        """
        cfg = self.cfg
        workers = max(1, min(int(cfg.workers), 1024))
        inflight_cap = max(16, workers * max(1, cfg.inflight_multiplier))
        iterator = iter(work)
        exhausted = False
        inflight = set()
        emfile_announced = False

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hant") as pool:

            def fill():
                nonlocal exhausted
                while (not self.stop_event.is_set() and not exhausted
                       and len(inflight) < inflight_cap):
                    try:
                        item = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    inflight.add(pool.submit(self.scan_port, *item))

            fill()
            while inflight:
                done, pending = wait(inflight, timeout=0.2, return_when=FIRST_COMPLETED)
                inflight = set(pending)
                for fut in done:
                    try:
                        res = fut.result()
                    except Exception as exc:  # defensive: scan_port shouldn't raise
                        res = None
                        if on_warning:
                            on_warning(f"internal worker error: {exc}")
                    if res is not None:
                        on_result(res)
                if self._emfile.is_set() and not emfile_announced:
                    emfile_announced = True
                    inflight_cap = max(16, inflight_cap // 2)
                    if on_warning:
                        with self._emfile_lock:
                            n = self._emfile_count
                        on_warning(
                            f"OS socket limit reached (EMFILE x{n}); reduced in-flight "
                            f"limit to {inflight_cap}. Use fewer --workers or run "
                            f"'ulimit -n 4096' to raise the file descriptor limit."
                        )
                if not exhausted:
                    fill()
                if on_tick:
                    on_tick()


def probe_port_state(address: str, port: int, timeout: float) -> str:
    """Lightweight single-port probe (used by watch mode). Returns a state."""
    try:
        s = socket.create_connection((address, port), timeout=timeout)
        s.close()
        return OPEN
    except ConnectionRefusedError:
        return CLOSED
    except (socket.timeout, TimeoutError):
        return TIMEOUT
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return UNREACHABLE
        return ERROR
