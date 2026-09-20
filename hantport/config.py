"""Configuration file handling with per-key validation and safe defaults."""
from __future__ import annotations

import json
import os
import pathlib

DEFAULTS = {
    "workers": 100,               # concurrent TCP connections
    "connect_timeout": 1.0,       # seconds to establish a connection
    "read_timeout": 1.5,          # seconds to wait for banner/protocol data
    "retries": 1,                 # extra attempts for TIMEOUT/ERROR results
    "profile": "common",          # default scan profile
    "output_dir": "~/.hantport/reports",
    "colors": True,
    "banner": True,               # collect service banners
    "service_detection": True,    # protocol probes / HTTP / TLS inspection
    "tls_inspection": True,       # TLS metadata (cert, version, verification)
    "max_cidr_hosts": 4096,       # per-CIDR expansion limit
}

_INT_RANGES = {
    "workers": (1, 1024),
    "retries": (0, 10),
    "max_cidr_hosts": (1, 1000000),
}


def default_config():
    cfg = dict(DEFAULTS)
    cfg["output_dir"] = os.path.expanduser(cfg["output_dir"])
    return cfg


def config_path():
    env = os.environ.get("HANT_CONFIG")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".hantport", "config.json")


def _validate(key, value):
    """Return (ok, value_or_message)."""
    dflt = DEFAULTS[key]
    if isinstance(dflt, bool):
        if isinstance(value, bool):
            return True, value
        return False, f"expected true or false, got {value!r}"
    if isinstance(dflt, int):
        if isinstance(value, bool) or not isinstance(value, int):
            return False, f"expected an integer, got {value!r}"
        lo, hi = _INT_RANGES.get(key, (0, 10 ** 9))
        if not lo <= value <= hi:
            return False, f"expected a value between {lo} and {hi}, got {value}"
        return True, value
    if isinstance(dflt, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False, f"expected a number, got {value!r}"
        if not 0.05 <= float(value) <= 120:
            return False, f"expected a value between 0.05 and 120, got {value}"
        return True, float(value)
    if isinstance(dflt, str):
        if not isinstance(value, str):
            return False, f"expected a string, got {value!r}"
        if key == "profile":
            from .ports import PROFILES
            if value not in PROFILES:
                return False, f"unknown profile '{value}' (choose: {', '.join(sorted(PROFILES))})"
        if key == "output_dir":
            value = os.path.expanduser(value)
        return True, value
    return False, f"unsupported key '{key}'"


def load_config(path=None):
    """Load configuration. Returns (config, warnings).

    A corrupted configuration is explained exactly and safe defaults are used.
    """
    cfg = default_config()
    warnings = []
    path = path or config_path()
    if not os.path.exists(path):
        return cfg, warnings
    try:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(f"Cannot read configuration file {path}: {exc}. Using defaults.")
        return cfg, warnings
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        warnings.append(
            f"Configuration file {path} is corrupted: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno}). Using defaults."
        )
        return cfg, warnings
    if not isinstance(data, dict):
        warnings.append(f"Configuration file {path} must contain a JSON object. Using defaults.")
        return cfg, warnings
    for key, value in data.items():
        if key not in DEFAULTS:
            warnings.append(f"Unknown configuration key '{key}' ignored.")
            continue
        ok, fixed = _validate(key, value)
        if ok:
            cfg[key] = fixed
        else:
            warnings.append(f"Invalid value for '{key}': {fixed}. Using default ({DEFAULTS[key]}).")
    return cfg, warnings
