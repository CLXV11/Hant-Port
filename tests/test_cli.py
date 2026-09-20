"""CLI-level tests: end-to-end behavior through the real entry points."""
import contextlib
import csv as csvmod
import io
import json
import signal
import socket
import subprocess
import sys
import time

import pytest

from hantport.cli import main

ROOT = __file__.rsplit("/", 2)[0]
PY = sys.executable


class FakeSock:
    def __init__(self, script):
        self._script = list(script)

    def settimeout(self, t):
        pass

    def recv(self, n):
        if self._script:
            return self._script.pop(0)
        raise socket.timeout()

    def sendall(self, b):
        pass

    def close(self):
        pass


def _transport(address, timeout=None):
    port = address[1]
    if port == 22:
        return FakeSock([b"SSH-2.0-OpenSSH_8.9\r\n"])
    if port == 80:
        return FakeSock([b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"])
    if port == 443:
        raise ConnectionRefusedError()
    return FakeSock([])


@pytest.fixture
def net(monkeypatch):
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", _transport)
    yield
    monkeypatch.setattr(socket, "create_connection", real)


class TestCliScan:
    def test_scan_json(self, net, capsys):
        rc = main(["scan", "127.0.0.1", "-p", "22,80,443", "--json",
                   "--no-save", "--no-color", "--no-tls", "--workers", "10",
                   "--retries", "0"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        res = {r["port"]: r for r in data["targets"][0]["addresses"][0]["results"]}
        assert res[22]["service"] == "ssh"
        assert res[80]["service"] == "http" and res[80]["http"]["status"] == 200
        assert res[443]["state"] == "CLOSED"

    def test_scan_csv(self, net, capsys):
        rc = main(["scan", "127.0.0.1", "-p", "22", "--csv",
                   "--no-save", "--no-color"])
        assert rc == 0
        rows = list(csvmod.reader(io.StringIO(capsys.readouterr().out)))
        assert rows[0][0] == "host" and rows[1][4] == "ssh"

    def test_scan_table(self, net, capsys):
        rc = main(["scan", "127.0.0.1", "-p", "22", "--no-save",
                   "--no-color", "-v"])
        out = capsys.readouterr().out
        assert rc == 0 and "OPEN" in out and "HIGH" in out

    @pytest.mark.parametrize("args", [
        ["scan", "999.1.1.1"],
        ["scan", "127.0.0.1", "-p", "80,80"],
        ["scan", "127.0.0.1", "-p", "70000"],
        ["scan", "127.0.0.1", "--profile", "custom"],
        ["scan", "missing file.txt"],
    ])
    def test_invalid_input_exit_2(self, args, capsys):
        assert main(args + ["--no-save"]) == 2
        assert "error:" in capsys.readouterr().err


class TestBundle:
    """The single-file hant.py must be self-contained and current."""

    def test_version_and_author(self):
        r = subprocess.run([PY, f"{ROOT}/hant.py", "--version"],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0
        assert "1.2.1" in r.stdout and "CLXV11" in r.stdout

    def test_bundle_help(self):
        r = subprocess.run([PY, f"{ROOT}/hant.py", "--help"],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "scan" in r.stdout


class TestWatchAndSignals:
    def test_sigint_during_scan_is_clean(self, net):
        p = subprocess.Popen(
            [PY, f"{ROOT}/hant.py", "scan", "10.255.255.1", "-p", "1-2000",
             "--timeout", "5", "--workers", "50", "--no-color", "--no-save"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(3)
        p.send_signal(signal.SIGINT)
        out, _ = p.communicate(timeout=30)
        assert p.returncode == 130
        assert "interrupted" in out.lower() and "partial" in out.lower()
