#!/usr/bin/env python3
"""
live_capture.py — Continuous passive network fingerprinting via live packet capture.

Runs indefinitely on a specified interface, processing packets as they arrive
and writing evidence incrementally to the database. Reuses the existing
analysis_functions.py logic — nothing is reimplemented here.

Usage:
    python live_capture.py [--iface IFACE]

Requires root / administrator privileges for raw socket access.
"""

import sys
import argparse
import signal
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, Ether, IP, TCP, DHCP, Raw

from database.db_utils import create_tables, add_evidence, register_source, update_source_stats
from scripts.analysis_functions import get_os_from_tcpip_sig, parse_dhcp_options, parse_http_user_agent
from scripts.pcap_utils import extract_mss_from_tcp_options, round_ttl
from config import LIVE_IFACE, PARSE_DEBUG, resolve_model_artifact_path

# ── in-memory dedup state ─────────────────────────────────────────────────────
# For tcp_ip: only emit evidence when we see a higher TTL (closer to the source).
best_ttl_seen: dict = {}
# For http: one UA evidence row per session is enough — store the first good UA.
seen_http: set = set()
# Session statistics
_stats = {"packets": 0, "evidence": 0, "macs": set()}
_pending_stats = {"packets": 0, "evidence": 0}
# Active source tag (set in main() from the chosen interface)
_source: str = "live:unknown"

# ── ML model (optional) ───────────────────────────────────────────────────────
_ml_model = None
_label_encoder = None
_expected_features = None


def _load_ml_model():
    global _ml_model, _label_encoder, _expected_features
    model_path = resolve_model_artifact_path()
    if model_path.exists():
        try:
            artifact = joblib.load(model_path)
            _ml_model = artifact["model"]
            _label_encoder = artifact["label_encoder"]
            _expected_features = artifact["feature_names"]
            print(f"[live_capture] ML model loaded from {model_path}")
        except Exception as e:
            print(f"[live_capture] Warning: could not load ML model — {e}")
    else:
        print("[live_capture] No ML model artifact found — using TTL-only OS fallback.")


# ── packet callback ───────────────────────────────────────────────────────────
def _process_packet(packet):
    _stats["packets"] += 1
    _pending_stats["packets"] += 1

    if not (packet.haslayer(Ether) and packet.haslayer(IP)):
        return

    mac = str(packet[Ether].src).lower()
    src_ip = str(packet[IP].src)
    _stats["macs"].add(mac)

    # ── TCP SYN → tcp_ip evidence ─────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        is_syn = (int(tcp.flags) & 0x12) == 0x02
        if is_syn:
            ttl = int(packet[IP].ttl)
            if mac not in best_ttl_seen or ttl > best_ttl_seen[mac]:
                best_ttl_seen[mac] = ttl

                src_port     = int(tcp.sport)
                tcp_syn_size = len(packet[IP])
                tcp_win      = int(tcp.window)
                tcp_mss      = extract_mss_from_tcp_options(tcp)
                ttl_rounded  = round_ttl(ttl)
                sig          = get_os_from_tcpip_sig(tcp, packet[IP])

                os_guess   = None
                match_conf = 0.0

                if _ml_model and _label_encoder and _expected_features:
                    df_feat = pd.DataFrame([{
                        "SRC_PORT":     src_port,
                        "TCP_SYN_SIZE": tcp_syn_size,
                        "TCP_WIN":      tcp_win,
                        "TCP_MSS":      tcp_mss,
                        "TTL":          ttl_rounded,
                    }])[_expected_features]
                    probas     = _ml_model.predict_proba(df_feat)
                    pred_idx   = int(np.argmax(probas, axis=1)[0])
                    os_guess   = str(_label_encoder.inverse_transform([pred_idx])[0])
                    match_conf = float(np.max(probas, axis=1)[0])
                else:
                    if ttl_rounded <= 64:
                        os_guess = "linux / android"
                    elif ttl_rounded <= 128:
                        os_guess = "windows"
                    else:
                        os_guess = "network gear"
                    match_conf = 0.5

                add_evidence(
                    mac_address=mac,
                    signal_type="tcp_ip",
                    raw_data={
                        "ip_address":   src_ip,
                        "src_port":     src_port,
                        "tcp_syn_size": tcp_syn_size,
                        "tcp_win":      tcp_win,
                        "tcp_mss":      tcp_mss,
                        "ttl":          ttl,
                        "sig":          sig,
                    },
                    matched_signature=os_guess,
                    match_confidence=match_conf,
                    source=_source,
                )
                _stats["evidence"] += 1
                _pending_stats["evidence"] += 1
                if PARSE_DEBUG:
                    print(f"[tcp_ip]  {mac} ({src_ip}) → {os_guess} ({match_conf:.2f})")

        # ── HTTP User-Agent → http evidence ───────────────────────────────
        if packet.haslayer(Raw) and mac not in seen_http:
            ua = parse_http_user_agent(packet[Raw].load)
            if ua:
                add_evidence(
                    mac_address=mac,
                    signal_type="http",
                    raw_data={"user_agent": ua, "ip_address": src_ip},
                    source=_source,
                )
                seen_http.add(mac)
                _stats["evidence"] += 1
                _pending_stats["evidence"] += 1
                if PARSE_DEBUG:
                    print(f"[http]    {mac} ({src_ip}) → {ua[:80]}")

    # ── DHCP → dhcp evidence ──────────────────────────────────────────────
    if packet.haslayer(DHCP):
        parsed = parse_dhcp_options(packet[DHCP])
        if parsed["option_55_param_list"] or parsed["option_60_vendor_class"] or parsed["hostname"]:
            dhcp_ip = parsed.get("requested_ip") or src_ip
            parsed["ip_address"] = dhcp_ip
            add_evidence(mac_address=mac, signal_type="dhcp", raw_data=parsed, source=_source)
            _stats["evidence"] += 1
            _pending_stats["evidence"] += 1
            if PARSE_DEBUG:
                hn  = parsed.get("hostname", "—")
                vc  = parsed.get("option_60_vendor_class", "—")
                print(f"[dhcp]    {mac} ({dhcp_ip}) hostname={hn} vendor_class={vc}")

    if _pending_stats["packets"] >= 250:
        update_source_stats(_source, packet_delta=_pending_stats["packets"], evidence_delta=_pending_stats["evidence"])
        _pending_stats["packets"] = 0
        _pending_stats["evidence"] = 0


# ── shutdown handler ──────────────────────────────────────────────────────────
def _shutdown(signum=None, frame=None):
    if _pending_stats["packets"] or _pending_stats["evidence"]:
        update_source_stats(_source, packet_delta=_pending_stats["packets"], evidence_delta=_pending_stats["evidence"])
        _pending_stats["packets"] = 0
        _pending_stats["evidence"] = 0

    print("\n" + "=" * 60)
    print("[live_capture] Capture stopped.")
    print(f"  Packets processed    : {_stats['packets']:,}")
    print(f"  Unique MACs seen     : {len(_stats['macs']):,}")
    print(f"  Evidence rows written: {_stats['evidence']:,}")
    print("=" * 60)
    sys.exit(0)


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Passive live network fingerprinting capture. Runs until Ctrl+C."
    )
    parser.add_argument(
        "--iface", default=LIVE_IFACE,
        help=f"Network interface to capture on (default from config: '{LIVE_IFACE}')",
    )
    args = parser.parse_args()
    global _source
    _source = f"live:{args.iface}"

    print("=" * 60)
    print("[live_capture] Starting passive live capture")
    print(f"  Interface : {args.iface}")
    print(f"  BPF filter: tcp or udp port 67 or udp port 68")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    create_tables()
    register_source(_source, "live")
    _load_ml_model()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    sniff(
        iface=args.iface,
        prn=_process_packet,
        filter="tcp or udp port 67 or udp port 68",
        store=0,      # don't buffer packets in RAM
    )


if __name__ == "__main__":
    main()
