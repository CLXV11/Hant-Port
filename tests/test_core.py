"""Core engine tests: parsing, states, detection, serialization, comparison."""
import errno
import io as _io
import json
import os
import socket

import pytest

from hantport.compare import compare_reports
from hantport.config import default_config, load_config
from hantport.output import scan_to_csv, scan_to_json
from hantport.ports import (parse_port_spec, port_hint, profile_ports,
                            profile_docs, top_ports)
from hantport.report import load_report, summarize
from hantport.scanner import (CLOSED, ERROR, OPEN, TIMEOUT, UNREACHABLE,
                              ScanConfig, ScanEngine, ScanStats)
from hantport.service import classify_banner, parse_http, sanitize_text
from hantport.targets import load_targets_file, parse_targets


# --------------------------------------------------------------------------
# Port specification parsing
# --------------------------------------------------------------------------
class TestPortSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("80", [80]),
        ("1-3,80", [1, 2, 3, 80]),
        (" 22 , 80-82 ", [22, 80, 81, 82]),
        ("1-100,443,9000-9002", list(range(1, 101)) + [443, 9000, 9001, 9002]),
    ])
    def test_valid_specs(self, spec, expected):
        assert parse_port_spec(spec) == expected

    @pytest.mark.parametrize("bad", ["0", "65536", "5-2", "80,80", "abc",
                                       "1-2-3", "", "  ", "80,", "-5", "1,,"])
    def test_invalid_specs_rejected(self, bad):
        with pytest.raises(Exception):
            parse_port_spec(bad)

    def test_duplicates_rejected(self):
        with pytest.raises(Exception) as exc:
            parse_port_spec("80,443,80")
        assert "Duplicate" in str(exc.value)


# --------------------------------------------------------------------------
# Profiles and service database
# --------------------------------------------------------------------------
class TestProfiles:
    def test_sizes(self):
        assert len(profile_ports("fast")) == 100
        assert len(profile_ports("full")) == 65535
        assert len(profile_ports("thorough")) == 10000
        assert len(profile_ports("common")) > 1024

    def test_top_ports(self):
        assert top_ports(5) == [80, 23, 443, 21, 22]
        assert len(top_ports(1000)) == 1000

    def test_db_is_hints_only(self):
        name, desc = port_hint(80)
        assert name == "http" and desc

    def test_docs_cover_all_profiles(self):
        assert set(profile_docs()) == {"fast", "common", "thorough", "full"}


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------
class TestTargets:
    def test_ipv4(self):
        t = parse_targets(["192.168.1.1"], 4096)
        assert t[0].addresses == ["192.168.1.1"] and not t[0].is_hostname

    def test_ipv6(self):
        t = parse_targets(["::1"], 4096)
        assert t[0].addresses == ["::1"]

    def test_hostname(self):
        t = parse_targets(["example.com"], 4096)
        assert t[0].is_hostname

    def test_cidr_expansion(self):
        t = parse_targets(["192.168.1.0/30"], 4096)
        assert len(t[0].addresses) == 4

    @pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0.0/33", "-host-",
                                       "a..b", "10.0.0.0/8"])
    def test_invalid_rejected(self, bad):
        with pytest.raises(Exception):
            parse_targets([bad], 4096)

    def test_target_file(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("# comment\n\n192.168.1.1\nexample.com\nnot a target !!\n"
                     "10.0.0.0/31\n")
        targets, invalid = load_targets_file(str(f), 4096)
        assert [t.original for t in targets] == ["192.168.1.1", "example.com",
                                                 "10.0.0.0/31"]
        assert len(invalid) == 1 and invalid[0][0] == 5


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
class TestConfig:
    def test_defaults(self):
        cfg = default_config()
        assert cfg["workers"] == 100 and cfg["profile"] == "common"

    def test_corrupted_config(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text('{"workers": 200, "broken": ')
        cfg, warns = load_config(str(f))
        assert cfg["workers"] == 100
        assert any("corrupted" in w for w in warns)

    def test_per_key_validation(self, tmp_path):
        import json as _json
        f = tmp_path / "config.json"
        f.write_text(_json.dumps({"workers": 250, "retries": 99,
                                  "colors": "yes", "profile": "nope",
                                  "connect_timeout": 0.5, "unknown_key": 1}))
        cfg, warns = load_config(str(f))
        assert cfg["workers"] == 250 and cfg["connect_timeout"] == 0.5
        assert cfg["colors"] is True and cfg["retries"] == 1
        assert len(warns) == 4


# --------------------------------------------------------------------------
# Banner hygiene + classification
# --------------------------------------------------------------------------
class TestBanner:
    def test_sanitize_strips_control_chars(self):
        dirty = b"hello\x1b]0;owned\x07\x1b[31m\x00world\r\n"
        clean = sanitize_text(dirty)
        assert "\x1b" not in clean and "\x07" not in clean
        assert "\x00" not in clean and "\r" not in clean and "\n" not in clean

    def test_sanitize_size_cap(self):
        assert len(sanitize_text(b"A" * 5000, 100)) <= 100

    @pytest.mark.parametrize("banner,svc,conf", [
        ("SSH-2.0-OpenSSH_8.9", "ssh", "HIGH"),
        ("+OK Dovecot ready.", "pop3", "HIGH"),
        ("* OK [CAPABILITY IMAP4rev1] ready", "imap", "HIGH"),
        ("RFB 003.008", "vnc", "HIGH"),
        ("220 ProFTPD Server ready.", "ftp", "HIGH"),
        ("220 mail.example ESMTP Postfix", "smtp", "HIGH"),
        ("@RSYNCD: 31.0", "rsync", "HIGH"),
        ("220 something unknown here", "ftp/smtp", "MEDIUM"),
    ])
    def test_classify(self, banner, svc, conf):
        name, confidence, _ = classify_banner(banner)
        assert name == svc and confidence == conf

    def test_garbage_not_classified(self):
        assert classify_banner("") is None
        assert classify_banner("random binary \x01\x02 junk") is None


# --------------------------------------------------------------------------
# HTTP parsing
# --------------------------------------------------------------------------
class TestHttp:
    RESP = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n"
            b"Content-Type: text/html\r\nContent-Length: 42\r\n\r\n")

    def test_parse_valid(self):
        info = parse_http(self.RESP, over_tls=False)
        assert info["status"] == 200 and info["server"] == "nginx/1.24"
        assert info["http_version"] == "HTTP/1.1" and info["protocol"] == "http"

    def test_parse_rejects_non_http(self):
        assert parse_http(b"SSH-2.0-OpenSSH\r\n", False) is None
        assert parse_http(b"", False) is None
        assert parse_http(b"GARBAGE\r\n\r\n", False) is None


# --------------------------------------------------------------------------
# Full engine with mocked transport
# --------------------------------------------------------------------------
class FakeSock:
    def __init__(self, script):
        self._script = list(script)
        self.closed = False

    def settimeout(self, t):
        pass

    def recv(self, n):
        if self._script:
            return self._script.pop(0)
        raise socket.timeout()

    def sendall(self, b):
        pass

    def close(self):
        self.closed = True


HTTP_RESP = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n"
             b"Content-Length: 42\r\n\r\n")


def _transport(address, timeout=None):
    port = address[1]
    if port == 22:
        return FakeSock([b"SSH-2.0-OpenSSH_8.9p1\r\n"])
    if port == 21:
        return FakeSock([b"220 ProFTPD ready.\r\n"])
    if port == 80:
        return FakeSock([HTTP_RESP])
    if port == 443:
        raise ConnectionRefusedError()
    if port == 3306:
        return FakeSock([b"\x0a" + b"5.7.38-log\x00x"])
    if port == 6379:
        return FakeSock([b"+PONG\r\n"])
    if port == 1337:
        raise socket.timeout()
    if port == 1338:
        raise OSError(errno.EHOSTUNREACH, "No route")
    return FakeSock([])


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", _transport)
    return ScanEngine(ScanConfig(workers=20, connect_timeout=0.3, retries=1))


class TestEngine:
    PORTS = [21, 22, 80, 443, 3306, 6379, 9000, 1337, 1338]

    def _run(self, eng):
        results = {}
        eng.run([("t", "10.0.0.1", p, None) for p in self.PORTS],
                lambda r: results.setdefault(r.port, r))
        return results

    def test_states(self, engine):
        r = self._run(engine)
        assert r[22].state == OPEN and r[22].service == "ssh"
        assert r[21].state == OPEN and r[21].service == "ftp"
        assert r[443].state == CLOSED and r[443].service == ""
        assert r[1337].state == TIMEOUT and "no response" in r[1337].reason
        assert r[1338].state == UNREACHABLE
        assert r[3306].state == OPEN and r[3306].service == "mysql"
        assert r[6379].state == OPEN and r[6379].service == "redis"
        assert r[9000].state == OPEN and r[9000].confidence == "LOW"
        assert r[9000].evidence == "port-number association only (no protocol evidence)"

    def test_http_detection(self, engine):
        r = self._run(engine)
        assert r[80].service == "http" and r[80].http["status"] == 200
        assert r[80].confidence == "HIGH"

    def test_stats_and_latency(self, engine):
        r = self._run(engine)
        assert all(x.latency_ms >= 0 for x in r.values())

    def test_emfile_reduces_and_warns(self, monkeypatch):
        calls = {"n": 0}

        def flaky(address, timeout=None):
            calls["n"] += 1
            if calls["n"] % 3 == 0:
                raise OSError(errno.EMFILE, "Too many open files")
            return FakeSock([])

        monkeypatch.setattr(socket, "create_connection", flaky)
        eng = ScanEngine(ScanConfig(workers=8, retries=0))
        got, warnings = [], []
        eng.run([("h", "10.0.0.1", p, None) for p in range(100, 130)],
                lambda r: got.append(r), on_warning=warnings.append)
        assert len(got) == 30
        assert warnings and "EMFILE" in warnings[0] and "ulimit" in warnings[0]


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------
def _results(engine):
    res = {}
    engine.run([("t", "10.0.0.1", p, None) for p in TestEngine.PORTS],
               lambda r: res.setdefault(r.port, r))
    return res


@pytest.fixture
def scan_data(engine):
    res = _results(engine)
    stats = ScanStats(len(res))
    for x in res.values():
        stats.add(x)
    entry = {"original": "10.0.0.1", "resolved": ["10.0.0.1"], "reverse": {},
             "ports_desc": "test", "addresses": {"10.0.0.1": list(res.values())}}
    return [entry], stats.snapshot()


class TestSerialization:
    def test_json_roundtrip(self, scan_data):
        entries, snap = scan_data
        data = scan_to_json(entries, ScanConfig(), snap, ["w"], "2026-01-01")
        parsed = json.loads(json.dumps(data))
        assert parsed["summary"]["open"] == 6   # 21,22,80,3306,6379,9000
        assert parsed["summary"]["closed"] == 1
        assert parsed["summary"]["timeout"] == 1

    def test_csv_wellformed(self, scan_data):
        import csv
        entries, _ = scan_data
        rows = list(csv.reader(_io.StringIO(scan_to_csv(entries))))
        assert rows[0][0] == "host"
        assert len(rows) == 1 + sum(len(v) for v in entries[0]["addresses"].values())


# --------------------------------------------------------------------------
# Compare + report loading
# --------------------------------------------------------------------------
def _mk(open_ports, banner=None, cert=None, svc=None):
    res = []
    for p in range(1, 11):
        st = "OPEN" if p in open_ports else "CLOSED"
        r = {"port": p, "state": st,
             "service": svc.get(p, "") if svc else ("http" if st == "OPEN" else ""),
             "banner": banner.get(p, "") if banner else "",
             "tls": {}, "reason": ""}
        if cert and p in cert:
            r["tls"] = {"certificate": cert[p]}
        res.append(r)
    return {"tool": "HANT PORT", "version": "1.2.1", "timestamp": "t",
            "summary": {}, "warnings": [],
            "targets": [{"target": "h", "resolved_addresses": [],
                         "reverse_dns": {},
                         "addresses": [{"address": "10.0.0.1", "results": res}]}]}


class TestCompare:
    def test_detects_all_change_kinds(self, tmp_path):
        c1 = {"sha256": "aaa", "not_after": "Jan  1 00:00:00 2030 GMT", "subject": "CN=old"}
        c2 = {"sha256": "bbb", "not_after": "Jan  1 00:00:00 2031 GMT", "subject": "CN=new"}
        old_f = tmp_path / "old.json"
        old_f.write_text(json.dumps(_mk({2, 4, 6})))
        new_f = tmp_path / "new.json"
        new_f.write_text(json.dumps(_mk({4, 6, 8}, banner={6: "b1"}, cert={4: c2},
                                        svc={8: "http"})))
        changes = compare_reports(str(old_f), str(new_f))
        kinds = [k for k, _ in changes]
        assert "NEW_OPEN" in kinds
        assert "PORT_CLOSED" in kinds
        assert "CERT_CHANGED" in kinds
        closed = [t for k, t in changes if k == "PORT_CLOSED"][0]
        assert "2/tcp" in closed and "was OPEN" in closed

    def test_no_changes(self, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text(json.dumps(_mk({2, 4})))
        b.write_text(json.dumps(_mk({2, 4})))
        assert compare_reports(str(a), str(b)) == []

    def test_corrupted_report_rejected(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        with pytest.raises(Exception):
            load_report(str(bad))
