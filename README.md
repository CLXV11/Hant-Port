# HANT PORT

<div align="center">

```
██╗  ██╗ █████╗ ███╗   ██╗████████╗
██║  ██║██╔══██╗████╗  ██║╚══██╔══╝
███████║███████║██╔██╗ ██║   ██║
██╔══██║██╔══██║██║╚██╗██║   ██║
██║  ██║██║  ██║██║ ╚████║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║
██╔═══╝ ██║   ██║██╔══██╗   ██║
██║     ╚██████╔╝██║  ██║   ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

**A production-grade, rootless TCP port scanner for Termux / Android.**

Honest port states. Evidence-based service detection. Zero fake features.

[![tests](https://github.com/CLXV11/Hant-Port/actions/workflows/tests.yml/badge.svg)](https://github.com/CLXV11/Hant-Port/actions/workflows/tests.yml)
[![Version](https://img.shields.io/badge/version-1.2.1-cyan?style=flat-square)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Termux%20%C2%B7%20Android%20%C2%B7%20Linux-green?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-CLXV11-orange?style=flat-square&logo=github)](https://github.com/CLXV11)
![visitors](https://komarev.com/ghpvc/?username=CLXV11&repo=Hant-Port&color=cyan&style=flat-square)

## Contents

- [Why HANT PORT exists](#why-hant-port-exists)
- [What it does](#what-it-does)
- [Quick start](#quick-start-termux)
- [Usage](#usage)
- [Reading the output](#reading-the-output)
- [Architecture](#architecture)
- [Testing](#testing)
- [Security & ethics](#security--ethics)
- [FAQ](#faq)


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=CLXV11/Hant-Port&type=Date)](https://star-history.com/#CLXV11/Hant-Port&Date)

 
</div>

---

## Why HANT PORT exists

Most "port scanner" repositories are one of two things: a 50-line
`socket.connect()` loop with a scary name, or a fake Hollywood UI that prints
canned output. HANT PORT is neither.

It was built around one rule: **never report what you cannot prove.**

- A timeout is never labeled *closed* — silence and refusal are different
  events, and the tool treats them differently.
- Port `80` is not "HTTP" because a table says so. It is HTTP when the service
  *proves* it — with a parsed response, a protocol banner, or a TLS handshake.
  Until then it is a *hint*, marked `LOW` confidence, always.
- Every feature in the menu is real. There are no placeholder buttons, no
  simulated progress, no detection without evidence.

## What it does

| Capability | Details |
|---|---|
| **TCP connect scanning** | Single IPs, hostnames, IPv4, IPv6, CIDR ranges, multiple targets, target files with comments |
| **Six honest port states** | `OPEN` `CLOSED` `TIMEOUT` `UNREACHABLE` `ERROR` `UNKNOWN` — with a human-readable reason for each |
| **Evidence-graded detection** | HIGH (protocol proof) / MEDIUM (partial evidence) / LOW (port-number hint only) |
| **Banner analysis** | Captures natural banners; strips terminal control characters so hostile banners cannot manipulate your terminal; size-capped |
| **Protocol probes** | Minimal, non-destructive: HTTP `GET /`, Redis `PING`, memcached `version` |
| **TLS inspection** | Version, cipher, certificate subject/issuer/validity, hostname match, verification result — self-signed handled correctly, never flagged as malicious |
| **HTTP inspection** | Status, server, content-type, content-length, redirect location, HTTP version |
| **Scan profiles** | `fast` (top 100) · `common` (1-1024 + top 100) · `thorough` (1-10000) · `full` (1-65535) · `custom` |
| **Bounded concurrency** | Worker pool with backpressure, retries, EMFILE detection and automatic in-flight reduction, fd-limit guard |
| **Live statistics** | Progress, per-state counts, rate, average latency, elapsed, ETA |
| **Reports** | Auto-saved JSON reports; `report latest`, `report list` |
| **Comparison** | `compare old.json new.json` — new open ports, closed ports, service/banner/certificate changes. Factual only, never "suspicious" |
| **Live monitoring** | `watch TARGET --ports 22,80 --interval 10` with timestamped transitions |
| **Rootless discovery** | TCP sweep of the LAN; raw ARP/ICMP honestly reported as unavailable without privileges |

## Quick start (Termux)

```sh
pkg install python

# Option A: single file, zero install
curl -L -o hant.py https://filebin.net/hantport13/hant.py
python hant.py

# Option B: full repo with installer
git clone https://github.com/CLXV11/hant-port.git
cd hant-port && bash install.sh
hant
```

## Usage

```sh
hant                          # interactive menu (7 actions, fully keyboard-driven)
hant scan 192.168.100.1 -p 22,80,443
hant scan example.com --top-ports 1000 --workers 200
hant scan 192.168.100.0/24 --profile fast
hant scan targets.txt --json -o result.json
hant scan 192.168.100.1 --profile common -v     # verbose: evidence + all states
hant watch 192.168.100.1 --ports 22,80 --interval 10
hant compare old.json new.json
hant report latest
hant discover                                   # find live hosts on your LAN
```

## Reading the output

```
PORT   STATE    SERVICE    CONF    DETAILS
22     OPEN     ssh        HIGH    SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10
80     OPEN     http       HIGH    200 OK | nginx/1.24
443    TIMEOUT  -          -       (silence — possible firewall)
3306   CLOSED   -          -       connection refused (RST)
```

**Confidence ladder**

| Level | Meaning |
|---|---|
| `HIGH` | The service proved itself: parsed HTTP response, protocol banner, TLS+HTTP, probe reply |
| `MEDIUM` | TLS handshake succeeded, or an ambiguous banner (e.g. a bare `220` greeting) |
| `LOW` | Known port association only — a hint, never a conclusion |

## Architecture

```
hant                  launcher
hant.py               single-file bundle (embeds the full package)
hantport/
  cli.py              argument parsing + scan orchestration
  scanner.py          TCP connect engine, bounded concurrency, port states
  service.py          banners, HTTP/TLS probes, confidence grading
  ports.py            service-association DB (hints), top-ports, profiles
  targets.py          target/CIDR/file parsing, DNS + reverse DNS
  output.py           console rendering, progress, JSON/CSV
  report.py           report persistence
  compare.py          factual report diffing
  watch.py            live monitoring
  discover.py         rootless LAN discovery
  config.py           validated configuration
  interactive.py      menu mode (same engines as CLI)
  util.py             logo, boxes, sanitization
tests/                66 pytest tests (engine, CLI, bundle, signals)
```

Design decisions worth knowing:

- **Connect scan, not SYN.** SYN scanning needs raw sockets → root. HANT PORT
  works with normal Termux permissions and says so honestly.
- **Backpressure, not unbounded queues.** At most `workers × 3` tasks are in
  flight; memory stays flat whether you scan 3 ports or 196,605.
- **Detection failures never break a scan.** If TLS parsing fails, you still
  get your port state.
- **Sanitized banners.** Control characters (including ESC) are stripped before
  anything touches your terminal.

## Testing

```sh
pip install pytest
python -m pytest tests/ -v
```

66 tests: port-spec validation, target/CIDR parsing, config corruption
recovery, banner classification, HTTP parsing, the full scan engine against a
mocked transport (including EMFILE backpressure), JSON/CSV serialization,
report comparison, CLI exit codes, Ctrl+C mid-scan, and the single-file bundle.

CI runs the same suite on Python 3.9 – 3.12 on every push.

## Performance

~5,400 ports/sec on loopback with 200 workers (`--no-detect`). On real
networks throughput is latency-bound; `--profile fast` against a home router
finishes in seconds.

## Security & ethics

HANT PORT is a **reconnaissance** tool. It sends no destructive payloads and
contains no exploitation functionality. Scan only networks and hosts you own
or have explicit permission to test — unauthorized scanning may be illegal in
your jurisdiction. The comparison engine reports *factual* changes and
deliberately avoids calling anything "suspicious" on its own.

## FAQ

**Why is the UI English-only?**
Terminal Arabic shaping is unreliable — glyphs render reversed and break
alignment in Termux and most terminals. English is the lingua franca of
security tooling (nmap, Metasploit, Burp) and renders correctly everywhere.

**Does it need root?**
No. Everything works with normal Termux permissions. Features that genuinely
require privileges (raw ARP/ICMP) say `NOT AVAILABLE WITHOUT PRIVILEGED
ACCESS` instead of pretending.

**How is this different from nmap?**
nmap is the industry standard and does far more (OS detection, NSE scripting,
dozens of scan types). HANT PORT is what you reach for on an unrooted phone
when you want honest states, evidence-graded service detection, and a single
file you can carry anywhere.

## Author

**CLXV11** — [github.com/CLXV11](https://github.com/CLXV11)

Built for Termux users who were tired of fake tools.

<div align="center">
If HANT PORT saved you time, a ⭐ means a lot.
</div>
