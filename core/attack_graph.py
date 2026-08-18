"""
core/attack_graph.py
Requirement 11: self-contained interactive attack graph as HTML using
vis-network via CDN (no Graphviz binary dependency). Requirement 3: escapes
all finding-derived text before embedding it in HTML/JS so a malicious
target response can't plant stored XSS into our own output.
"""
from __future__ import annotations

import html
import json

from core.correlator import AttackChain
from core.schema import Finding

SEVERITY_COLOR = {
    "critical": "#ff1744",
    "high": "#ff6d00",
    "medium": "#ffd600",
    "low": "#39FF14",
    "info": "#8892a0",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyFoxGuard Attack Graph</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  :root {{ --cfx-green: #39FF14; --cfx-bg: #0d0d0d; }}
  body {{ margin:0; background: var(--cfx-bg); color: #e8e8e8; font-family: -apple-system, Segoe UI, Roboto, sans-serif; }}
  h1 {{ color: var(--cfx-green); text-shadow: 0 0 8px rgba(57,255,20,0.5); padding: 16px 24px; margin: 0; border-bottom: 1px solid rgba(57,255,20,0.3); }}
  #graph {{ width: 100vw; height: calc(100vh - 64px); }}
  .legend {{ position: fixed; bottom: 12px; right: 12px; background: #121212; border: 1px solid rgba(57,255,20,0.4); border-radius: 8px; padding: 10px 14px; font-size: 12px; }}
  .legend span {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; }}
</style>
</head>
<body>
<h1>CyFoxGuard &mdash; Interactive Attack Graph</h1>
<div id="graph"></div>
<div class="legend">
  <div><span style="background:#ff1744"></span>Critical</div>
  <div><span style="background:#ff6d00"></span>High</div>
  <div><span style="background:#ffd600"></span>Medium</div>
  <div><span style="background:#39FF14"></span>Low</div>
  <div><span style="background:#8892a0"></span>Info / Chain</div>
</div>
<script>
  const nodes = new vis.DataSet({nodes_json});
  const edges = new vis.DataSet({edges_json});
  const container = document.getElementById('graph');
  const data = {{ nodes, edges }};
  const options = {{
    nodes: {{ shape: 'dot', size: 16, font: {{ color: '#e8e8e8' }}, borderWidth: 2 }},
    edges: {{ color: {{ color: 'rgba(57,255,20,0.5)' }}, arrows: 'to', smooth: true }},
    physics: {{ stabilization: true, barnesHut: {{ gravitationalConstant: -8000 }} }},
    interaction: {{ hover: true }}
  }};
  new vis.Network(container, data, options);
</script>
</body>
</html>"""


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def build_attack_graph_html(findings: list[Finding], chains: list[AttackChain]) -> str:
    nodes = []
    edges = []
    finding_by_id = {f.id: f for f in findings}

    for f in findings:
        nodes.append({
            "id": f.id,
            "label": _esc(f.title)[:60],
            "title": _esc(f"{f.vulnerability_type} @ {f.endpoint} [{f.severity.value}/{f.confidence.value}]"),
            "color": SEVERITY_COLOR.get(f.severity.value, "#8892a0"),
        })

    for idx, chain in enumerate(chains):
        chain_node_id = f"chain-{idx}"
        nodes.append({
            "id": chain_node_id,
            "label": _esc(chain.name),
            "title": _esc(f"Risk score: {chain.risk_score}/100\\n{chain.description}"),
            "color": "#8892a0",
            "shape": "box",
            "font": {"color": "#0d0d0d"},
        })
        for fid in chain.finding_ids:
            if fid in finding_by_id:
                edges.append({"from": fid, "to": chain_node_id})

    html_out = TEMPLATE.format(
        nodes_json=json.dumps(nodes),
        edges_json=json.dumps(edges),
    )
    return html_out
