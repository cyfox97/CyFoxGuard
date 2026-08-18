"""
core/banner.py
Branding requirement: on CLI startup, before anything else runs, print
"CyFoxGuard" using a typewriter animation, one character at a time,
~40ms delay, in glossy parrot-green (#39FF14 / ANSI 256 color 118).
"""
import sys
import time

GREEN = "\033[38;5;118m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER_TEXT = "CyFoxGuard"
SUBTITLE = "Web & API Penetration Testing Toolkit"
CHAR_DELAY = 0.04  # ~40ms


def show_banner(animate: bool = True, stream=sys.stdout) -> None:
    """Prints the CyFoxGuard banner. Disable animation (animate=False) for
    non-interactive / CI output so logs stay clean."""
    stream.write(f"{BOLD}{GREEN}")
    if animate and stream.isatty():
        for ch in BANNER_TEXT:
            stream.write(ch)
            stream.flush()
            time.sleep(CHAR_DELAY)
    else:
        stream.write(BANNER_TEXT)
    stream.write(f"{RESET}\n")
    stream.write(f"{GREEN}{SUBTITLE}{RESET}\n")
    stream.write(f"{GREEN}{'-' * len(SUBTITLE)}{RESET}\n\n")
    stream.flush()
