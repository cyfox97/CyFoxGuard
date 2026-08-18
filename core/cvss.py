"""
core/cvss.py
Minimal, correct CVSS 3.1 base-score calculator so every finding gets a real
vector + score instead of just a severity label (requirement 5).
Implements the official FIRST.org CVSS 3.1 base-metric equations.
"""
from __future__ import annotations

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) * 10000 / 100000


def cvss31_score(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> tuple[str, float]:
    """
    Returns (vector_string, base_score) for CVSS 3.1.
    s: "C" (changed) or "U" (unchanged) scope.
    """
    iss = 1 - ((1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a]))
    pr_table = PR_CHANGED if s == "C" else PR_UNCHANGED

    if s == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * AV[av] * AC[ac] * pr_table[pr] * UI[ui]

    if impact <= 0:
        base_score = 0.0
    elif s == "C":
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base_score = _roundup(min(impact + exploitability, 10))

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return vector, round(base_score, 1)


# Pre-built profiles used by modules so scoring is consistent and defensible.
PROFILES = {
    "sqli_confirmed": dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "sqli_probe": dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "xss_reflected": dict(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "xss_stored": dict(av="N", ac="L", pr="N", ui="N", s="C", c="L", i="L", a="N"),
    "bola_confirmed": dict(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N"),
    "bola_suspected": dict(av="N", ac="L", pr="L", ui="N", s="U", c="L", i="N", a="N"),
    "jwt_alg_none": dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "jwt_weak_secret": dict(av="N", ac="H", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "missing_header": dict(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="N", a="N"),
    "rate_limit_missing": dict(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="L"),
    "shadow_api": dict(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "anomaly": dict(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "account_takeover_chain": dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
}


def score_profile(name: str) -> tuple[str, float]:
    p = PROFILES[name]
    return cvss31_score(**p)
