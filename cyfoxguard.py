#!/usr/bin/env python3
"""
cyfoxguard.py
CyFoxGuard — Web & API Penetration Testing Toolkit.

Usage:
  python cyfoxguard.py --target https://example.com [options]

This file is intentionally the ONLY entry point. The authorization gate
(core.auth_gate.require_authorization) is called unconditionally before any
scan module is imported/executed, and there is no flag anywhere in this
parser that can skip it.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import show_banner
from core.auth_gate import require_authorization
from core.config import ScanConfig
from core.logging_utils import get_logger
from core.schema import SEVERITY_ORDER, Confidence, Finding, FindingStore, Severity

log = get_logger("cyfoxguard")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyfoxguard.py",
        description="CyFoxGuard — Web & API Penetration Testing Toolkit (Linux)",
    )
    p.add_argument("--target", required=True, help="Target base URL, e.g. https://example.com")
    p.add_argument("--safe", action="store_true", help="Reduced blast-radius mode for real, live, authorized targets")
    p.add_argument("--ci", action="store_true", help="Non-interactive mode; reads authorization from env var, exits with a pass/fail code")
    p.add_argument("--fail-on", default="critical", choices=["info", "low", "medium", "high", "critical"], help="In --ci mode, exit 1 if any CONFIRMED/HIGH+ finding at or above this severity exists")
    p.add_argument("--openapi-spec", default=None, help="Path to an OpenAPI/Swagger spec file for shadow-API diffing")
    p.add_argument("--identity", action="append", default=[], help="name:HeaderName=HeaderValue, repeatable, min 2 for BOLA/IDOR testing")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    p.add_argument("--output-dir", default="cyfoxguard_output", help="Directory to write JSON, HTML report, and attack graph into")
    p.add_argument("--no-external-tools", action="store_true", help="Disable auto-detection/use of sqlmap, ffuf, dalfox, Burp")
    p.add_argument("--dashboard", action="store_true", help="Launch the local web dashboard after the scan completes")
    p.add_argument("--dashboard-port", type=int, default=5151)
    return p


def parse_identities(raw: list[str]) -> list[dict]:
    identities = []
    for item in raw:
        try:
            name, hdr = item.split(":", 1)
            hname, hval = hdr.split("=", 1)
            identities.append({"name": name, "headers": {hname: hval}})
        except ValueError:
            log.warning(f"Ignoring malformed --identity value: {item!r} (expected name:Header=Value)")
    return identities


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # 1. Branding banner — before anything else runs.
    show_banner(animate=not args.ci)

    # 2. Mandatory, non-skippable authorization gate.
    require_authorization(ci_mode=args.ci, target=args.target)

    # From here on, network modules are imported/used.
    from core.http_client import HttpClient
    from core.external_tools import detect_tools
    from core.baseline import BaselineTracker
    from core.correlator import correlate
    from core.report import generate_html_report
    from core.attack_graph import build_attack_graph_html
    from modules import (
        security_headers, sql_injection, xss, openapi_shadow,
        jwt_analysis, bola_idor, rate_limiting,
    )

    config = ScanConfig(
        target=args.target,
        safe_mode=args.safe,
        ci_mode=args.ci,
        fail_on=args.fail_on,
        timeout=args.timeout,
        output_dir=args.output_dir,
        identities=parse_identities(args.identity),
        openapi_spec=args.openapi_spec,
        use_external_tools=not args.no_external_tools,
    )

    if config.safe_mode:
        log.info("Running in --safe mode: rate-limit flood test skipped, SQLi/XSS reduced to single probe payload.")

    os.makedirs(config.output_dir, exist_ok=True)

    client = HttpClient(timeout=config.timeout)
    tools = detect_tools() if config.use_external_tools else __import__("core.external_tools", fromlist=["ToolAvailability"]).ToolAvailability()

    store = FindingStore()
    baseline = BaselineTracker()

    def baseline_hook(endpoint, elapsed_ms, size, status):
        baseline.observe(endpoint, elapsed_ms, size, status)

    log.info(f"Starting scan against {config.target}")

    module_calls = [
        ("security_headers", lambda: security_headers.run(client, config, baseline_hook)),
        ("sql_injection", lambda: sql_injection.run(client, config, tools, baseline_hook)),
        ("xss", lambda: xss.run(client, config, tools, baseline_hook)),
        ("openapi_shadow", lambda: openapi_shadow.run(client, config, baseline_hook)),
        ("jwt_analysis", lambda: jwt_analysis.run(client, config, baseline_hook)),
        ("bola_idor", lambda: bola_idor.run(client, config, baseline_hook)),
        ("rate_limiting", lambda: rate_limiting.run(client, config, baseline_hook)),
    ]

    for name, fn in module_calls:
        log.info(f"Running module: {name}")
        try:
            results = fn()
            for f in results:
                store.add(f)
        except Exception as e:
            log.error(f"Module {name} raised an exception and was skipped: {e}")

    # Anomaly pass: re-check the target's landing page against the now-built baseline.
    resp = client.get(config.target)
    anomaly = baseline.check_deviation(config.target, resp.elapsed_ms, len(resp.text), resp.status_code)
    if anomaly:
        store.add(anomaly)

    findings = store.all()
    log.info(f"Scan complete: {len(findings)} unique findings after deduplication.")

    chains = correlate(findings)
    log.info(f"Attack-chain correlation: {len(chains)} chain(s) identified.")

    # --- Write JSON output (requirement 3: tokens redacted, never written in full) ---
    from core.report import compute_security_score
    json_output = {
        "target": config.target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "safe_mode": config.safe_mode,
        "security_score": compute_security_score(findings),
        "counts_by_severity": {sev.value: sum(1 for f in findings if f.severity == sev) for sev in Severity},
        "findings": [f.to_dict() for f in findings],
        "chains": [c.to_dict() for c in chains],
    }
    json_path = os.path.join(config.output_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(json_output, fp, indent=2)
    log.info(f"JSON output written to {json_path}")

    # --- HTML report ---
    html_report = generate_html_report(findings, chains, config, tools.summary())
    report_path = os.path.join(config.output_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as fp:
        fp.write(html_report)
    log.info(f"HTML report written to {report_path}")

    # --- Attack graph ---
    graph_html = build_attack_graph_html(findings, chains)
    graph_path = os.path.join(config.output_dir, "attack_graph.html")
    with open(graph_path, "w", encoding="utf-8") as fp:
        fp.write(graph_html)
    log.info(f"Attack graph written to {graph_path}")

    # --- CI/CD gate ---
    exit_code = 0
    if args.ci:
        threshold = SEVERITY_ORDER[Severity(args.fail_on)]
        blocking = [
            f for f in findings
            if SEVERITY_ORDER[f.severity] >= threshold
            and f.confidence in (Confidence.CONFIRMED, Confidence.HIGH)
        ]
        if blocking:
            log.error(f"--fail-on {args.fail_on}: {len(blocking)} finding(s) at/above threshold with high/confirmed confidence.")
            exit_code = 1
        else:
            log.info(f"--fail-on {args.fail_on}: no blocking findings.")

    if args.dashboard and not args.ci:
        from core.dashboard import run_dashboard
        log.info(f"Launching dashboard at http://127.0.0.1:{args.dashboard_port}")
        run_dashboard(json_path, graph_path, port=args.dashboard_port)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
