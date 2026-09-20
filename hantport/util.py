"""Shared helpers for HANT PORT."""
from __future__ import annotations

import re
import sys

APP_NAME = "HANT PORT"
APP_VERSION = "1.2.1"
AUTHOR = "CLXV11"
GITHUB_URL = "https://github.com/CLXV11"


class InputError(Exception):
    """A user-facing input validation error (bad IP, port, file, ...)."""


def sanitize_text(data: "bytes | None", limit: int = 1024) -> str:
    """Decode banner bytes safely.

    Strips terminal control characters (including ESC) so that hostile or
    buggy banners cannot manipulate the user's terminal. Never raises.
    """
    if not data:
        return ""
    raw = bytes(data[:limit])
    text = raw.decode("utf-8", errors="replace")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # Strip C0/C1 control characters and DEL.
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)
    return text.strip()


def truncate(text: str, limit: int = 140) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


class Palette:
    """ANSI color palette; a no-op when colors are disabled or not a TTY."""

    CODES = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
    }

    def __init__(self, enabled: bool = True):
        self.enabled = bool(enabled) and sys.stdout.isatty()

    def color(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        prefix = "".join(self.CODES[n] for n in names if n in self.CODES)
        return f"{prefix}{text}{self.CODES['reset']}"

    def state(self, state: str) -> str:
        return {
            "OPEN": self.color("OPEN", "green", "bold"),
            "CLOSED": self.color("CLOSED", "dim"),
            "TIMEOUT": self.color("TIMEOUT", "yellow"),
            "UNREACHABLE": self.color("UNREACHABLE", "yellow"),
            "ERROR": self.color("ERROR", "red"),
            "UNKNOWN": self.color("UNKNOWN", "magenta"),
        }.get(state, state)


LOGO = r"""
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
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝"""


def show_logo(palette, subtitle=""):
    """Print the HANT PORT logo with a cyan->green gradient."""
    lines = LOGO.strip("\n").splitlines()
    n = len(lines)
    for i, line in enumerate(lines):
        if i < n // 2:
            print(palette.color(line, "cyan", "bold"))
        else:
            print(palette.color(line, "green", "bold"))
    if subtitle:
        print(palette.color(subtitle.center(37), "yellow"))


def box_top(palette, title="", width=52):
    if title:
        t = f" {title} "
        left = (width - len(t) - 2) // 2
        right = width - len(t) - 2 - left
        return palette.color("╔" + "═" * left + t + "═" * right + "╗", "cyan", "bold")
    return palette.color("╔" + "═" * width + "╗", "cyan", "bold")


def box_bottom(palette, width=52):
    return palette.color("╚" + "═" * width + "╝", "cyan", "bold")


_ANSI_RE = None


def _plain_len(text):
    global _ANSI_RE
    if _ANSI_RE is None:
        import re as _re
        _ANSI_RE = _re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    return len(_ANSI_RE.sub("", text))


def box_line(palette, text, width=52):
    pad = max(1, width - _plain_len(text))
    return palette.color("║ ", "cyan") + text + " " * pad + palette.color("║", "cyan")
