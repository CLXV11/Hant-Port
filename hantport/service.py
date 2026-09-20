"""Service identification for open ports.

Evidence sources, in order of reliability:
  1. Protocol banners the server sends naturally (SSH, FTP, SMTP, POP3, IMAP,
     VNC/RFB, rsync, MySQL handshake).
  2. Conservative protocol-aware probes (minimal HTTP GET, Redis PING,
     memcached version) -- non-destructive by construction.
  3. TLS handshakes (metadata + verification result, self-signed handled).
  4. HTTP responses (status line + headers).
  5. The known port association table -- HINT ONLY, always LOW confidence.

Every identification carries a confidence level and an evidence string.
"""
from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import tempfile

from .ports import port_hint
from .util import APP_VERSION, sanitize_text

# Servers that normally transmit a banner immediately upon connect.
BANNER_FIRST_PORTS = {21, 22, 25, 110, 143, 873, 3306, 5900, 5901}

# Ports worth sending a minimal HTTP request to.
HTTP_PROBE_PORTS = {
    80, 81, 300, 3000, 3128, 5000, 591, 593, 6800, 7001, 7100, 7510, 7777,
    8000, 8008, 8010, 8020, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8090,
    8098, 8100, 8118, 8123, 8180, 8181, 8222, 8243, 8280, 8443, 8500, 8530,
    8800, 8888, 8983, 9000, 9001, 9042, 9060, 9080, 9090, 9091, 9100, 9200,
    9299, 9443, 9800, 9981, 9999, 10000, 10250, 10443, 11371, 12443, 16080,
    18080, 19000, 20000, 20720, 28017, 49152,
}

# Ports where a TLS handshake is likely.
TLS_HINT_PORTS = {
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1443, 2376,
    3269, 4443, 5061, 5223, 5351, 5671, 5986, 6697, 8443, 8834, 8883,
    8991, 9043, 9443, 9444, 9631, 16993,
}

MAX_BANNER_BYTES = 1024
MAX_HTTP_READ = 16384
_TLS_VERSIONS = None


def _unverified_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _recv_best_effort(sock, n):
    try:
        return sock.recv(n)
    except (OSError, socket.timeout, TimeoutError):
        return b""


def classify_banner(text: str):
    """Classify a text banner. Returns (service, confidence, evidence) or None."""
    if not text:
        return None
    t = text.strip()
    low = t.lower()
    if t.startswith(("SSH-2.0-", "SSH-1.99-", "SSH-1.5-")):
        return ("ssh", "HIGH", "SSH protocol banner")
    if low.startswith(("http/1.", "http/2 ")):
        return ("http", "HIGH", "HTTP response bytes received")
    if low.startswith("+ok"):
        return ("pop3", "HIGH", "POP3 greeting (+OK)")
    if low.startswith("* ok") or (low.startswith("*") and "imap" in low):
        return ("imap", "HIGH", "IMAP greeting (* OK)")
    if t.startswith("RFB "):
        return ("vnc", "HIGH", "RFB protocol version banner")
    if t.startswith("@RSYNCD:"):
        return ("rsync", "HIGH", "rsync daemon greeting")
    if t.startswith("220"):
        if "ftp" in low:
            return ("ftp", "HIGH", "FTP server banner (220)")
        if "smtp" in low or "esmtp" in low or "mail" in low or "postfix" in low or "sendmail" in low:
            return ("smtp", "HIGH", "SMTP greeting (220)")
        return ("ftp/smtp", "MEDIUM", "220 greeting, protocol ambiguous")
    return None


def _decode_pem_cert(pem: str):
    """Decode a PEM certificate using CPython's ssl test helper if available."""
    decode = getattr(ssl._ssl, "_test_decode_cert", None)
    if decode is None:
        return None
    fd, path = tempfile.mkstemp(prefix="hant-cert-", suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
        return decode(path)
    except Exception:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _name_to_str(name) -> str:
    parts = []
    for rdn in name or []:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _cert_summary(decoded: dict, der: bytes = None):
    if not decoded:
        return None
    cert = {
        "subject": _name_to_str(decoded.get("subject")),
        "issuer": _name_to_str(decoded.get("issuer")),
        "not_before": decoded.get("notBefore", ""),
        "not_after": decoded.get("notAfter", ""),
        "sans": [v for k, v in decoded.get("subjectAltName", ()) if k == "DNS"],
    }
    if der:
        cert["sha256"] = hashlib.sha256(der).hexdigest()
    return cert


def _cert_names(cert) -> list:
    names = list(cert.get("sans") or [])
    subject = cert.get("subject") or ""
    m = re.search(r"CN=([^,]+)", subject)
    if m and m.group(1) not in names:
        names.append(m.group(1))
    return names


def _hostname_matches(hostname: str, patterns) -> bool:
    host = hostname.lower().rstrip(".")
    for pattern in patterns or []:
        p = pattern.lower().rstrip(".")
        if p == host:
            return True
        if p.startswith("*."):
            if host.endswith(p[1:]) and host.count(".") == p.count("."):
                return True
    return False


def inspect_tls(host: str, port: int, server_hostname, timeout: float) -> dict:
    """Perform a TLS handshake and collect metadata.

    Tries a fully verified handshake first; if that fails (self-signed,
    expired, mismatch...) an unverified handshake is attempted purely to
    collect certificate metadata. Verification failure is reported as
    information, never as proof of maliciousness.
    """
    info = {
        "handshake": False, "tls_version": None, "cipher": None,
        "verified": False, "verification": "not attempted",
        "hostname_match": None, "certificate": None, "error": None,
    }
    der = None
    decoded = None
    # Attempt 1: verified handshake.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=server_hostname) as s:
                info["handshake"] = True
                info["verified"] = True
                info["verification"] = "OK"
                info["tls_version"] = s.version()
                info["cipher"] = s.cipher()[0] if s.cipher() else None
                decoded = s.getpeercert()
                der = s.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        info["verification"] = f"FAILED: {str(exc)[:160]}"
    except ssl.SSLError as exc:
        info["verification"] = f"FAILED: {str(exc)[:160]}"
    except OSError as exc:
        info["error"] = f"TLS handshake failed (connection): {exc}"
        return info

    if not info["handshake"]:
        # Attempt 2: unverified handshake for metadata only.
        try:
            ctx = _unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as raw:
                raw.settimeout(timeout)
                with ctx.wrap_socket(raw, server_hostname=None) as s:
                    info["handshake"] = True
                    info["tls_version"] = s.version()
                    info["cipher"] = s.cipher()[0] if s.cipher() else None
                    der = s.getpeercert(binary_form=True)
        except (ssl.SSLError, OSError) as exc:
            info["error"] = f"TLS handshake failed: {str(exc)[:160]}"
            return info

    if der:
        info["certificate"] = _cert_summary(decoded, der) if decoded else \
            _cert_summary(_decode_pem_cert(ssl.DER_cert_to_PEM_cert(der)), der)
    if server_hostname and info["certificate"]:
        info["hostname_match"] = _hostname_matches(server_hostname, _cert_names(info["certificate"]))
    return info


def _read_http_response(sock, limit):
    data = b""
    try:
        while len(data) < limit:
            try:
                chunk = sock.recv(min(4096, limit - len(data)))
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except OSError:
        pass
    return data


def parse_http(data: bytes, over_tls: bool):
    """Parse an HTTP response. Returns info dict or None if not HTTP."""
    if not data:
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = head.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "protocol": "https" if over_tls else "http",
        "http_version": parts[0],
        "status": status,
        "reason": parts[2] if len(parts) > 2 else "",
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "content_length": headers.get("content-length", ""),
        "location": headers.get("location", ""),
    }


def inspect_http(host: str, port: int, server_hostname, timeout: float, over_tls: bool = False):
    """Send one minimal, valid, non-destructive HTTP request.

    Returns (info_dict_or_None, raw_response_text).
    """
    s = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        if over_tls:
            s = _unverified_context().wrap_socket(raw, server_hostname=server_hostname)
        else:
            s = raw
    except (OSError, ssl.SSLError):
        return None, ""
    try:
        host_header = server_hostname or host
        request = (
            f"GET / HTTP/1.0\r\nHost: {host_header}\r\n"
            f"User-Agent: hant-port/{APP_VERSION}\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="replace")
        s.sendall(request)
        data = _read_http_response(s, MAX_HTTP_READ)
    except (OSError, ssl.SSLError):
        s.close()
        return None, ""
    s.close()
    return parse_http(data, over_tls), sanitize_text(data, MAX_BANNER_BYTES)


def _probe_exchange(host: str, port: int, payload: bytes, timeout: float, expect_prefix: bytes):
    """Open a fresh connection, send payload, read one response."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    except OSError:
        return b""
    try:
        s.sendall(payload)
        return s.recv(512)
    except OSError:
        return b""
    finally:
        s.close()


def inspect_service(sock, address: str, port: int, server_hostname, result, cfg):
    """Populate service/confidence/evidence/banner/http/tls on an OPEN result.

    `sock` is the already-connected socket for the port. Probes that need a
    fresh connection (HTTP/TLS) open additional short-lived connections.
    Never raises.
    """
    service, confidence, evidence = "", "", ""
    banner_bytes = b""
    http_info, tls_info = {}, {}

    # --- 1. Passive banner (only where servers speak first) -----------------
    if cfg.grab_banners and port in BANNER_FIRST_PORTS:
        sock.settimeout(min(cfg.read_timeout, 1.5))
        banner_bytes = _recv_best_effort(sock, 2048)

    if banner_bytes and port == 3306 and banner_bytes[0] == 0x0A:
        ver = banner_bytes[1:].split(b"\x00")[0]
        if re.match(rb"^\d+\.\d+", ver):
            service, confidence, evidence = "mysql", "MEDIUM", "MySQL handshake packet"
    if not service:
        guess = classify_banner(sanitize_text(banner_bytes))
        if guess:
            service, confidence, evidence = guess

    # --- 2. Minimal protocol probes ----------------------------------------
    if not service and port == 6379:
        reply = _probe_exchange(address, port, b"PING\r\n", cfg.connect_timeout, b"+PONG")
        if reply.startswith(b"+PONG"):
            service, confidence, evidence = "redis", "HIGH", "redis replied +PONG to PING"
    if not service and port == 11211:
        reply = _probe_exchange(address, port, b"version\r\n", cfg.connect_timeout, b"VERSION")
        if reply.startswith(b"VERSION "):
            service, confidence, evidence = "memcached", "HIGH", "memcached replied to 'version'"

    # --- 3. HTTP (plain) -----------------------------------------------------
    if not service and port in HTTP_PROBE_PORTS:
        info, raw = inspect_http(address, port, server_hostname, cfg.connect_timeout)
        if info:
            http_info = info
            service, confidence, evidence = ("https" if port in TLS_HINT_PORTS else "http"), "HIGH", \
                f"HTTP response (status {info['status']})"
        elif raw and not banner_bytes:
            guess = classify_banner(raw)
            if guess:
                service, confidence, evidence = guess
                banner_bytes = raw.encode("utf-8", errors="replace")

    # --- 4. TLS ---------------------------------------------------------------
    tls_done = False
    if (not service or port in TLS_HINT_PORTS) and cfg.tls_inspection and port in TLS_HINT_PORTS:
        tls_info = inspect_tls(address, port, server_hostname, max(cfg.connect_timeout * 3, 3.0))
        tls_done = True
        if tls_info.get("handshake"):
            hint = port_hint(port)
            if not service:
                if hint:
                    service, confidence, evidence = hint[0], "MEDIUM", "TLS handshake succeeded"
                else:
                    service, confidence, evidence = "tls", "MEDIUM", "TLS handshake succeeded"
            # HTTPS: try HTTP over the TLS-protected service.
            if port in (443, 8443, 9443, 10443, 4443, 8530, 12443):
                info, _raw = inspect_http(address, port, server_hostname,
                                          cfg.connect_timeout, over_tls=True)
                if info:
                    http_info = info
                    service, confidence, evidence = "https", "HIGH", \
                        f"TLS handshake + HTTP response (status {info['status']})"

    # --- 5. Fallback: known-port association is a HINT ONLY -------------------
    if not service:
        hint = port_hint(port)
        if hint:
            service, confidence, evidence = hint[0], "LOW", "port-number association only (no protocol evidence)"

    result.service = service
    result.confidence = confidence
    result.evidence = evidence
    if banner_bytes:
        result.banner = sanitize_text(banner_bytes, MAX_BANNER_BYTES)
    result.http = http_info
    result.tls = tls_info
