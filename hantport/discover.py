"""Local network discovery without root.

Raw ARP and raw ICMP require privileged access and are NOT faked here.
Without root, discovery uses TCP connect sweeps on a small set of common
ports, which is honest: only hosts with at least one responsive TCP port
are found, and this is stated clearly in the output.
"""
from __future__ import annotations

import ipaddress
import socket

from .scanner import OPEN, ScanConfig, ScanEngine, ScanStats
from .targets import resolve_target

DEFAULT_DISCOVERY_PORTS = [80, 443, 22, 445, 139, 21, 23, 3389, 8080, 53]


def local_ip():
    """Best-effort local IPv4 detection (no traffic is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # TEST-NET-1; UDP sends nothing
        ip = s.getsockname()[0]
        if ip:
            return ip
    except OSError:
        pass
    finally:
        s.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def run_discover(console, cfg, ports=None, workers=None, timeout=None, network=None):
    console.banner()
    console.kv("Method", "TCP connect sweep (no root required)")
    console.info("Raw ARP / ICMP discovery: NOT AVAILABLE WITHOUT PRIVILEGED ACCESS")
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            console.error(f"Invalid network '{network}': {exc}")
            return 2
    else:
        ip = local_ip()
        if not ip:
            console.error("Could not determine a local IP address. The device may be offline "
                          "(airplane mode?) or have no active network interface.")
            return 1
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        console.kv("Local IP", ip)
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 2 else [str(net.network_address)]
    console.kv("Network", str(net))
    console.kv("Hosts", str(len(hosts)))
    console.kv("Probe ports", ",".join(str(p) for p in ports))
    console.rule()

    scfg = ScanConfig(
        workers=workers or 50,
        connect_timeout=timeout or 0.6,
        read_timeout=0.5,
        retries=0,
        detect_services=False,
    )
    engine = ScanEngine(scfg)
    stats = ScanStats(len(hosts) * len(ports))
    alive = {}

    def on_result(res):
        stats.add(res)
        if res.state == OPEN:
            alive.setdefault(res.address, []).append(res.port)
        console.info(f"\r    probed {stats.snapshot()['done']}/{stats.snapshot()['total']}"
                     f"   alive so far: {len(alive)}   ",)
    work = ((h, h, p, None) for h in hosts for p in ports)
    engine.run(work, on_result)
    console.info("")

    if not alive:
        console.info("No live hosts found. Note: TCP-only discovery cannot see hosts with "
                     "all probed ports closed/filtered.")
        return 0
    print(f"{'IP ADDRESS':<18}{'HOSTNAME':<30}OPEN PROBE PORTS")
    for addr in sorted(alive, key=lambda a: [int(x) for x in a.split(".")] if a.count(".") == 3 else [0]):
        target = type("T", (), {"original": addr, "addresses": [addr], "is_hostname": False})
        res = resolve_target(target)
        hostname = res.reverse.get(addr, "-")
        print(f"{addr:<18}{hostname:<30}{','.join(str(p) for p in sorted(alive[addr]))}")
    print(f"\nFound {len(alive)} live host(s) out of {len(hosts)} probed.")
    return 0
