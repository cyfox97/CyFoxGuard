"""
core/dashboard.py
Requirement 12: local web dashboard (Flask) reading the JSON output, styled
per the branding section (dark background, glossy parrot-green accent
consistently across every page). All Jinja2 templates below use Flask's
default autoescape=True, so finding data pulled from the JSON (which may
contain fragments echoed back from the target) is escaped before rendering.
"""
from __future__ import annotations

import json
import os

from flask import Flask, jsonify, render_template

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "dashboard")
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


def create_app(json_output_path: str, attack_graph_path: str | None = None) -> Flask:
    app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

    def load_data():
        with open(json_output_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @app.route("/")
    def index():
        data = load_data()
        return render_template(
            "index.html",
            target=data.get("target"),
            security_score=data.get("security_score"),
            findings=data.get("findings", []),
            chains=data.get("chains", []),
            counts_by_severity=data.get("counts_by_severity", {}),
            generated_at=data.get("generated_at"),
            has_graph=attack_graph_path is not None,
        )

    @app.route("/findings")
    def findings():
        data = load_data()
        return render_template("findings.html", findings=data.get("findings", []))

    @app.route("/chains")
    def chains():
        data = load_data()
        return render_template("chains.html", chains=data.get("chains", []), findings=data.get("findings", []))

    @app.route("/graph")
    def graph():
        return render_template("graph.html", has_graph=attack_graph_path is not None)

    @app.route("/attack-graph-embed")
    def attack_graph_embed():
        if not attack_graph_path or not os.path.exists(attack_graph_path):
            return "<p style='color:#e8e8e8;background:#0d0d0d;font-family:sans-serif;padding:20px;'>No attack graph available.</p>"
        with open(attack_graph_path, "r", encoding="utf-8") as f:
            return f.read()

    @app.route("/api/data")
    def api_data():
        return jsonify(load_data())

    return app


def run_dashboard(json_output_path: str, attack_graph_path: str | None = None, host: str = "127.0.0.1", port: int = 5151):
    app = create_app(json_output_path, attack_graph_path)
    app.run(host=host, port=port, debug=False)
