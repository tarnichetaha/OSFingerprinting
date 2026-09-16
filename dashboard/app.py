#!/usr/bin/env python3
"""
dashboard/app.py — Flask dashboard for the OS Fingerprinting pipeline.

Start with:
    python dashboard/app.py

Then open http://127.0.0.1:5000
"""

import sys
import json
import dataclasses
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from flask import Flask, jsonify, render_template, abort

from database.db_utils import (
    get_all_devices, get_device_by_mac, get_recent_evidence,
    get_all_sources, get_source_summary, get_devices_by_source,
    get_evidence_by_source, create_tables,
)
from config import DASHBOARD_PORT, LOW_CONFIDENCE_THRESHOLD, MODEL_DIR

app = Flask(__name__, template_folder="templates")


NOT_RECORDED = {"Not Recorded", "Unknown", "unknown", "", None}


def _is_not_recorded(value) -> bool:
    """Return True for placeholders like blank/unknown without crashing on lists/dicts."""
    if isinstance(value, str):
        return value.strip() in {"", "Not Recorded", "Unknown", "unknown"}
    try:
        return value in NOT_RECORDED
    except TypeError:
        # Lists/dicts are valid payloads and should be preserved.
        return False

def _is_low_confidence(device) -> bool:
    fields = [
        device.confidence_os_family,
        device.confidence_os_version,
        device.confidence_device_type,
    ]
    for conf in fields:
        if conf > 0.0 and conf < LOW_CONFIDENCE_THRESHOLD:
            return True
    return False


def _device_to_dict(device) -> dict:
    d = dataclasses.asdict(device)
    d["low_confidence"] = _is_low_confidence(device)
    d.pop("evidence", None)
    return d


def _evidence_to_dict(ev) -> dict:
    d = dataclasses.asdict(ev)
    return d


def _filter_recorded(raw: dict) -> dict:
    """Strip keys whose values are blank / 'Not Recorded' / None."""
    return {k: v for k, v in raw.items() if not _is_not_recorded(v)}


def _serialize_evidence_rows(rows) -> list[dict]:
    result = []
    for evidence in rows:
        payload = _evidence_to_dict(evidence)
        if isinstance(payload.get("raw_data"), dict):
            payload["raw_data"] = _filter_recorded(payload["raw_data"])
        result.append(payload)
    return result



@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    devices = get_all_devices()
    return jsonify([_device_to_dict(d) for d in devices])


@app.route("/api/device/<mac>")
def api_device(mac):
    device = get_device_by_mac(mac)
    if not device:
        abort(404)
    d = _device_to_dict(device)
    d["evidence"] = _serialize_evidence_rows(device.evidence)
    return jsonify(d)


@app.route("/api/activity")
def api_activity():
    rows = get_recent_evidence(50)
    return jsonify(_serialize_evidence_rows(rows))


@app.route("/api/probe/<mac>", methods=["POST"])
def api_probe(mac):
    """Trigger an active nmap probe for the given MAC. Returns updated device JSON."""
    try:
        from scripts.active_probe import probe_device
        device = probe_device(mac)
        return jsonify(_device_to_dict(device))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/sources")
def api_sources():
    sources = get_all_sources()
    return jsonify(sources)


@app.route("/api/sources/<path:source_name>")
def api_source_detail(source_name):
    summary = get_source_summary(source_name)
    if not summary:
        abort(404)
    devices = get_devices_by_source(source_name)
    summary["devices"] = [_device_to_dict(d) for d in devices]
    return jsonify(summary)


@app.route("/api/sources/<path:source_name>/evidence")
def api_source_evidence(source_name):
    rows = get_evidence_by_source(source_name)
    return jsonify(_serialize_evidence_rows(rows))


@app.route("/api/model-metrics")
def api_model_metrics():
    metrics_path = MODEL_DIR / "os_classifier_metrics.json"
    if not metrics_path.exists():
        abort(404)
    with open(metrics_path, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


if __name__ == "__main__":
    create_tables()
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=True)
