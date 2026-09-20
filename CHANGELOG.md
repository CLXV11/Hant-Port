# Changelog

All notable changes to HANT PORT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.2.1] - 2026-09-20
### Added
- Author credit (CLXV11) in banner, `--version`, config screen and interactive mode
- GitHub URL reference throughout the tool

## [1.2.0] - 2026-09-20
### Added
- Professional ASCII logo with cyan-to-green gradient
- Boxed, colored, numbered interactive main menu
- Boxed setup screens for every interactive flow
- ANSI-aware table/box alignment (padding computed on visible text only)

### Changed
- Interactive UI is now English-only: terminal Arabic shaping is unreliable
  and reversed glyphs break alignment in Termux and most terminals

## [1.1.0] - 2026-09-20
### Added
- Interactive menu mode (`hant` with no arguments) with 7 numbered actions
- Same engines reused between CLI and interactive paths - zero duplicated logic

## [1.0.0] - 2026-09-19
### Added
- Initial release: TCP connect scanner with six honest port states
  (OPEN / CLOSED / TIMEOUT / UNREACHABLE / ERROR / UNKNOWN)
- Bounded-concurrency engine with backpressure, retries, EMFILE detection
  and automatic in-flight reduction
- Evidence-based service identification with HIGH/MEDIUM/LOW confidence;
  port-number associations are hints only and always marked LOW
- Banner grabbing with terminal-control-character sanitization
- Minimal non-destructive protocol probes (HTTP GET, Redis PING, memcached version)
- TLS inspection: version, cipher, certificate metadata, hostname match and
  verification result (self-signed certificates handled correctly)
- HTTP inspection: status, server, content-type, content-length, location
- Scan profiles: fast / common / thorough / full / custom
- Output modes: table, quiet, verbose, JSON, CSV; `--no-color` respected
- Report system with auto-save and `report latest|list|<name>`
- Report comparison: new open ports, closed ports, service/banner/cert changes
- Live watch mode with timestamped state transitions
- Rootless network discovery (TCP sweep; ARP/ICMP honestly reported unavailable)
- Target files with comments and per-line invalid reporting
- Configuration file with per-key validation and safe defaults
- Single-file `hant.py` bundle for Termux
