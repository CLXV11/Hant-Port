"""Target parsing, validation, DNS resolution and reverse DNS."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

from .util import InputError

MAX_CIDR_HOSTS = 4096

_HOST_LABEL = re.compile(r"^[A-Za-z0-9-]{1,63}$")
_IPV4_SHAPED = re.compile(r"^\d{1,3}(\.\d{1,3}){3,}$")


def _looks_like_broken_ipv4(s: str) -> bool:
    """True for dotted-quad-ish strings that are not valid IPv4 addresses."""
    return bool(_IPV4_SHAPED.match(s)) and True


@dataclass
class Target:
    original: str                      # what the user typed
    addresses: list = field(default_factory=list)  # expanded IPs (CIDR), else [original]
    is_hostname: bool = False


@dataclass
class Resolution:
    target: Target
    addresses: list = field(default_factory=list)  # [(ip, version)] actually scanned
    reverse: dict = field(default_factory=dict)    # ip -> PTR name (best effort)
    error: str = ""


def _valid_hostname(name: str) -> bool:
    if len(name) > 253:
        return False
    if name.endswith("."):
        name = name[:-1]
    labels = name.split(".")
    for label in labels:
        if not _HOST_LABEL.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def parse_target(spec: str, max_cidr: int = MAX_CIDR_HOSTS):
    """Parse one target spec: IPv4/IPv6 literal, hostname, or CIDR range."""
    s = (spec or "").strip()
    if not s:
        raise InputError("Empty target specification.")
    try:
        ipaddress.ip_address(s)
        return [Target(original=s, addresses=[s])]
    except ValueError:
        pass
    if _looks_like_broken_ipv4(s):
        raise InputError(f"Invalid target '{s}': looks like an IPv4 address but is malformed.")
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise InputError(f"Invalid CIDR target '{s}': {exc}.")
        if net.num_addresses > max_cidr:
            raise InputError(
                f"CIDR '{s}' expands to {net.num_addresses} addresses "
                f"(limit {max_cidr}). Use --max-targets to raise the limit."
            )
        if net.version == 6 and net.prefixlen < 112:
            raise InputError(
                f"Refusing to expand IPv6 CIDR '{s}': {net.num_addresses} addresses is "
                f"too many (limit {max_cidr})."
            )
        normalized = str(net)
        note = f" (normalized to network address {normalized})" if normalized != s else ""
        targets = [Target(original=s + note, addresses=[str(ip) for ip in net])]
        return targets
    if _valid_hostname(s):
        return [Target(original=s, is_hostname=True)]
    raise InputError(
        f"Invalid target '{s}': not a valid IPv4/IPv6 address, hostname, or CIDR range."
    )


def parse_targets(specs, max_cidr: int = MAX_CIDR_HOSTS):
    out = []
    for spec in specs:
        out.extend(parse_target(spec, max_cidr))
    return out


def load_targets_file(path: str, max_cidr: int = MAX_CIDR_HOSTS):
    """Load targets from a text file.

    Blank lines are ignored; lines starting with '#' or ';' are comments.
    Invalid lines are reported, not silently dropped.
    Returns (targets, invalid_lines) where invalid_lines is [(lineno, text, error)].
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise InputError(f"Cannot read target file '{path}': {exc.strerror or exc}.")
    targets, invalid = [], []
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            targets.extend(parse_target(line, max_cidr))
        except InputError as exc:
            invalid.append((lineno, line, str(exc)))
    return targets, invalid


def resolve_target(target: Target) -> Resolution:
    """Resolve a Target into concrete IP addresses (DNS where needed)."""
    if not target.is_hostname:
        addrs = []
        for a in target.addresses:
            try:
                ver = ipaddress.ip_address(a).version
            except ValueError:
                ver = 4
            addrs.append((a, ver))
        res = Resolution(target=target, addresses=addrs)
    else:
        try:
            infos = socket.getaddrinfo(target.original, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            return Resolution(target=target, error=f"DNS resolution failed: {exc}.")
        seen, addrs = set(), []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.add(addr)
                addrs.append((addr, 6 if info[0] == socket.AF_INET6 else 4))
        if not addrs:
            return Resolution(target=target, error="DNS resolution returned no addresses.")
        res = Resolution(target=target, addresses=addrs)
    # Reverse DNS (best effort, never fatal).
    for addr, _ver in res.addresses:
        try:
            res.reverse[addr] = socket.gethostbyaddr(addr)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
    return res
