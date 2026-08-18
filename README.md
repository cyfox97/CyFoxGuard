# CyFoxGuard

**Web & API Penetration Testing Toolkit** for Linux, Python 3.11+.

CyFoxGuard is built around one idea: be honest about what automated scanning
can and can't do. It does **not** claim zero false positives, does **not**
claim "unhackable" software, and does **not** claim guaranteed zero-day
detection. Instead it does the achievable, defensible version of each —
explicit confidence levels, dual-signal confirmation, a hardened codebase,
and a statistical-anomaly layer that's labeled exactly for what it is: a
heuristic aid for a human, not an AI oracle.

> **Only use this against systems you own or have explicit, documented
> authorization to test.** Unauthorized scanning is illegal in most
> jurisdictions. CyFoxGuard enforces an authorization gate before any scan
> runs and it is not skippable via any flag.

## Install

```bash
git clone <this-repo-url> cyfoxguard
cd cyfoxguard
pip install -r requirements.txt
```

Optional external tools CyFoxGuard will auto-detect and prefer when present
on `PATH` (falls back to built-in equivalents if absent, so it works
standalone with nothing else installed): `sqlmap`, `ffuf`, `dalfox`, and a
running Burp Suite Pro instance with its REST API reachable at
`127.0.0.1:1337`.

## Quick start

```bash
python cyfoxguard.py --target https://your-authorized-target.example
```

You'll be shown the authorization warning and prompted to type `yes` before
any request is sent.

### Safe mode (recommended for real, live, authorized targets)

```bash
python cyfoxguard.py --target https://your-authorized-target.example --safe
```

`--safe` skips the rate-limit flood test entirely and reduces SQLi/XSS
testing to a single low-impact probe payload instead of the full set. Same
modules, same JSON schema, lower blast radius.

### CI/CD mode

```bash
export CYFOXGUARD_AUTHORIZED=I_HAVE_AUTHORIZATION
python cyfoxguard.py --target https://staging.example --ci --fail-on high
```

Exits `0` if nothing at/above `--fail-on` was found with high/confirmed
confidence, `1` otherwise, `2` if authorization wasn't granted. See
`.github/workflows/cyfoxguard.yml` for a ready-to-use pipeline.

### View results

```bash
python cyfoxguard.py --target https://your-authorized-target.example --dashboard
```

Opens a local dark-themed dashboard at `http://127.0.0.1:5151`. Every scan
also writes `report.html` (full assessment report), `attack_graph.html`
(standalone interactive graph, no server needed), and `findings.json` into
the output directory.

## Try it safely first

`docker-compose.yml` + `DEMO.md` bring up OWASP Juice Shop and OWASP crAPI —
disposable, intentionally-vulnerable lab targets — with the exact commands
to run CyFoxGuard against each.

## What it checks

Seven modules, each producing findings in one shared schema (severity,
confidence, CWE, OWASP mapping, CVSS 3.1 vector+score, evidence,
remediation):

1. **Security Headers** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
   Referrer-Policy, Permissions-Policy, version-disclosing `Server` headers.
2. **SQL Injection** — error-signature + response-differential dual-signal
   detection; upgrades to `sqlmap` when available.
3. **XSS** — unique-marker reflection + HTML-executable-context dual-signal
   detection; upgrades to `dalfox` when available.
4. **OpenAPI Parser + Shadow API Diff** — finds live endpoints that respond
   but aren't in your OpenAPI spec.
5. **JWT Analysis** — `alg:none` acceptance, RS256→HS256 algorithm confusion,
   weak/guessable HMAC secrets.
6. **Multi-Identity BOLA/IDOR** — cross-identity object-level authorization
   testing (needs 2+ `--identity` values).
7. **Rate Limiting** — bounded burst test for 429 enforcement and
   `Retry-After` (skipped under `--safe`).

Plus:

- **Anomaly layer**: baselines response timing/size/status per endpoint
  during recon, flags statistically significant deviations as
  `category: anomaly, confidence: low` — explicitly not a signature match,
  explicitly requiring manual review.
- **Deterministic attack-chain correlation**: rule-based combination logic
  (e.g. weak JWT + confirmed BOLA = account-takeover chain), risk-scored
  0–100. Optional `ANTHROPIC_API_KEY`-powered narrative rewrite of an
  *already-decided* chain's prose — the AI never decides whether a chain
  exists.
- **Deduplication**: findings fingerprint on
  `(vulnerability_type, endpoint, parameter, root_cause)`; collisions
  collapse into one finding with an `instance_count`.

## Hardening (the achievable version of "unhackable")

- No `subprocess` call uses `shell=True`; every external-tool invocation
  uses a fixed argv list.
- All HTML output (report, dashboard, attack graph) is rendered through
  Jinja2/Flask with autoescaping on, so a malicious target can't plant
  stored XSS into CyFoxGuard's own output.
- Auth tokens are redacted to first/last 4 characters in logs and are never
  written to JSON output in full.
- Dependencies are pinned in `requirements.txt`.

## CLI reference

```
--target URL              Required. Base URL to scan.
--safe                     Reduced blast-radius mode.
--ci                       Non-interactive; reads CYFOXGUARD_AUTHORIZED env var.
--fail-on LEVEL             info|low|medium|high|critical (default: critical)
--openapi-spec PATH        Spec file for shadow-API diffing.
--identity name:Header=Value  Repeatable; 2+ enables BOLA/IDOR testing.
--timeout SECONDS          Per-request timeout (default 10).
--output-dir DIR           Output directory (default cyfoxguard_output).
--no-external-tools        Disable sqlmap/ffuf/dalfox/Burp auto-detection.
--dashboard                 Launch the local dashboard after scanning.
--dashboard-port PORT      Dashboard port (default 5151).
```

## Platform

Linux only. Not tested on or intended for Windows/macOS.

## Optional: AI narrative enrichment

Set `ANTHROPIC_API_KEY` in your environment to have attack-chain
descriptions rewritten as report-friendly prose. This is cosmetic only —
whether a chain exists, its risk score, and its component findings are
decided entirely by the deterministic rules in `core/correlator.py` before
the AI ever sees them.
