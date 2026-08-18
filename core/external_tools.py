"""
core/external_tools.py
Requirement 8: auto-detect and upgrade to sqlmap, ffuf, dalfox (via PATH) and
Burp Suite Pro (via its REST API at 127.0.0.1:1337) when available; fall back
to built-in equivalent checks otherwise.

Requirement 3 (hardening): every subprocess invocation here uses a fixed
argv list (never shell=True), and any user-controlled value (the target URL)
is passed as a single argv element rather than interpolated into a shell
string, so it cannot be used for shell injection.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

import requests

from core.logging_utils import get_logger

log = get_logger("external_tools")

BURP_API_BASE = "http://127.0.0.1:1337"
SUBPROCESS_TIMEOUT = 60


@dataclass
class ToolAvailability:
    sqlmap: bool = False
    ffuf: bool = False
    dalfox: bool = False
    burp: bool = False

    def summary(self) -> str:
        found = [name for name, ok in self.__dict__.items() if ok]
        return f"External tools detected: {', '.join(found) if found else 'none (using built-in checks)'}"


def detect_tools() -> ToolAvailability:
    avail = ToolAvailability(
        sqlmap=shutil.which("sqlmap") is not None,
        ffuf=shutil.which("ffuf") is not None,
        dalfox=shutil.which("dalfox") is not None,
    )
    try:
        r = requests.get(f"{BURP_API_BASE}/", timeout=1.5)
        avail.burp = r.status_code < 500
    except requests.RequestException:
        avail.burp = False
    log.info(avail.summary())
    return avail


def _run_argv(argv: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
    """
    Hardened subprocess runner: fixed argv list, shell=True is never used,
    no untrusted string is ever concatenated into a shell command.
    """
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list")
    return subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_sqlmap_probe(url: str, param: str, safe_mode: bool) -> str:
    """Runs a single, low-noise sqlmap batch check against one parameter."""
    argv = [
        "sqlmap", "-u", url, "-p", param,
        "--batch", "--level=1" if safe_mode else "--level=2",
        "--risk=1", "--random-agent",
    ]
    try:
        proc = _run_argv(argv)
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning(f"sqlmap invocation failed: {e}")
        return ""


def run_ffuf_probe(url_with_fuzz_marker: str, wordlist: str) -> str:
    argv = [
        "ffuf", "-u", url_with_fuzz_marker, "-w", wordlist,
        "-mc", "200,201,204,301,302,401,403", "-of", "json", "-s",
    ]
    try:
        proc = _run_argv(argv)
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning(f"ffuf invocation failed: {e}")
        return ""


def run_dalfox_probe(url: str, safe_mode: bool) -> str:
    argv = ["dalfox", "url", url, "--silence"]
    if safe_mode:
        argv += ["--skip-bav"]
    try:
        proc = _run_argv(argv)
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning(f"dalfox invocation failed: {e}")
        return ""


def burp_active_scan(url: str) -> dict | None:
    """Kicks off a Burp Suite Pro scan via its REST API, if reachable."""
    try:
        resp = requests.post(
            f"{BURP_API_BASE}/v0.1/scan",
            json={"urls": [url]},
            timeout=5,
        )
        if resp.status_code in (200, 201):
            return resp.json() if resp.content else {"status": "started"}
    except requests.RequestException as e:
        log.warning(f"Burp REST API call failed: {e}")
    return None
