#!/usr/bin/env python3
"""
active_probe.py — On-demand active OS + service fingerprinting for a single device.

Two-stage approach:
  1. RustScan sweeps the full TCP port range fast to find which ports are open
     (falls back to plain nmap full-range scan if RustScan isn't installed).
  2. nmap runs OS detection + service/version detection ONLY against the ports
     RustScan found open — much faster than letting nmap scan the full range
     itself, same depth of result.

Usage (CLI):
    python active_probe.py --mac AA:BB:CC:DD:EE:FF

Callable from the dashboard or other scripts:
    from active_probe import probe_device
    updated_device = probe_device("aa:bb:cc:dd:ee:ff")
"""

import sys
import os
import re
import shutil
import subprocess
import argparse
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from database.db_utils import get_device_by_mac, add_evidence
from config import PARSE_DEBUG

# ── Port -> device-type hint table ────────────────────────────────────────────
# Format: { port: (device_type_string, confidence_0_to_1) }
# Only ports where the implication is reasonably strong are included.
# Generic ports (80, 443) are excluded -- far too ambiguous.
PORT_TYPE_HINTS: dict = {
    9100: ("printer",      0.85),   # RAW / JetDirect
    631:  ("printer",      0.85),   # IPP
    515:  ("printer",      0.80),   # LPD / LPR
    554:  ("camera",       0.80),   # RTSP
    8554: ("camera",       0.75),   # Alternate RTSP
    1935: ("camera",       0.65),   # RTMP streaming
    22:   ("server",       0.60),   # SSH -- Linux/Unix/server
    23:   ("network_gear", 0.55),   # Telnet -- old gear or embedded
    161:  ("network_gear", 0.70),   # SNMP -- routers/switches
    162:  ("network_gear", 0.65),   # SNMP trap
    179:  ("network_gear", 0.80),   # BGP -- routing device
    3389: ("computer",     0.70),   # RDP -- Windows desktop/server
    5900: ("computer",     0.55),   # VNC
    548:  ("computer",     0.65),   # AFP -- macOS file sharing
}

# RustScan tuning -- conservative on purpose. This runs against a single home
# device chosen deliberately by the user, not a network sweep, but embedded/
# IoT gear can still behave oddly under a fast, high-concurrency port sweep.
RUSTSCAN_BATCH_SIZE = 3000
RUSTSCAN_TIMEOUT_MS = 3000


# ── RustScan: fast port discovery ─────────────────────────────────────────────

def _rustscan_available() -> bool:
    return shutil.which("rustscan") is not None


def rustscan_discover_ports(ip_address: str) -> list[int]:
    """
    Fast full-range TCP port discovery. Returns a list of open port numbers,
    or an empty list if RustScan isn't installed or found nothing.
    Discovery only -- no service/version detection, that's nmap's job next.
    """
    if not _rustscan_available():
        return []

    cmd = [
        "rustscan",
        "-a", ip_address,
        "-b", str(RUSTSCAN_BATCH_SIZE),
        "-t", str(RUSTSCAN_TIMEOUT_MS),
        "-g",              # greppable output: "ip -> [port, port, ...]"
        "--accessible",    # no ASCII art / color codes, easier to parse
    ]

    if PARSE_DEBUG:
        print(f"[active_probe] RustScan: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        print("[active_probe] RustScan timed out -- falling back to plain nmap.")
        return []
    except Exception as e:
        print(f"[active_probe] RustScan failed ({e}) -- falling back to plain nmap.")
        return []

    if result.returncode != 0:
        if PARSE_DEBUG:
            print(f"[active_probe] RustScan returned nonzero: {result.stderr}")
        return []

    match = re.search(r"\[(.*?)\]", result.stdout)
    if not match:
        return []
    return [int(p) for p in match.group(1).split(",") if p.strip().isdigit()]


# ── nmap wiring ────────────────────────────────────────────────────────────────

def _require_nmap():
    """Import nmap and verify the binary is reachable. Raises RuntimeError with install hint if not."""
    try:
        import nmap as _nmap
    except ImportError:
        raise RuntimeError(
            "python-nmap is not installed.\n"
            "  pip install python-nmap\n"
            "Also install the nmap binary:\n"
            "  Linux/Debian : sudo apt install nmap\n"
            "  macOS        : brew install nmap\n"
            "  Windows      : https://nmap.org/download.html"
        )
    try:
        scanner = _nmap.PortScanner()
    except _nmap.PortScannerError:
        raise RuntimeError(
            "nmap binary not found. Install it and make sure it is on your PATH:\n"
            "  Linux/Debian : sudo apt install nmap\n"
            "  macOS        : brew install nmap\n"
            "  Windows      : https://nmap.org/download.html"
        )
    return _nmap, scanner


def probe_device(mac_address: str):
    """
    Run an active RustScan + nmap OS + service scan for the device identified
    by mac_address.

    Args:
        mac_address: Target device MAC (case-insensitive, any delimiter).

    Returns:
        Updated Device object.

    Raises:
        ValueError:   Device not in DB, or has no known IP.
        RuntimeError: nmap binary/package not available, or scan failed.
    """
    mac = mac_address.lower()
    _nmap, scanner = _require_nmap()   # raises RuntimeError if missing

    device = get_device_by_mac(mac)
    if not device:
        raise ValueError(f"Device {mac} not found in the database.")
    if not device.ip_address_current:
        raise ValueError(
            f"Device {mac} has no recorded IP address -- cannot probe. "
            "Capture some traffic from this device first."
        )

    target_ip = device.ip_address_current
    source_tag = f"active:{target_ip}"

    # ── prominent active-probe notice ─────────────────────────────────────
    print()
    print("!" * 70)
    print("  [ACTIVE PROBE] Sending active scan (RustScan discovery + nmap analysis)")
    print(f"  Target IP  : {target_ip}")
    print(f"  Target MAC : {mac}")
    print("!" * 70)
    print()

    # ── stage 1: RustScan port discovery ─────────────────────────────────
    print(f"[active_probe] Stage 1: RustScan port discovery on {target_ip} ...")
    discovered_ports = rustscan_discover_ports(target_ip)

    if discovered_ports:
        print(f"[active_probe] RustScan found {len(discovered_ports)} open port(s): "
              f"{sorted(discovered_ports)}")
        nmap_ports_arg = ",".join(str(p) for p in discovered_ports)
        nmap_arguments = f"-O -sV --osscan-guess -p {nmap_ports_arg}"
        discovery_method = "rustscan"
    else:
        print("[active_probe] RustScan unavailable or found nothing -- "
              "falling back to nmap's own full-range discovery (slower).")
        nmap_arguments = "-O -sV --osscan-guess"
        discovery_method = "nmap_fallback"

    # record the raw discovery step as its own evidence, independent of nmap's
    # eventual service/OS analysis -- useful to see even if nmap's pass fails
    add_evidence(
        mac_address=mac,
        signal_type="active_port_discovery",
        raw_data={
            "ip_address": target_ip,
            "open_ports": sorted(discovered_ports),
            "method": discovery_method,
        },
        matched_signature=None,
        match_confidence=None,
        source=source_tag,
    )

    # ── stage 2: nmap OS + service analysis on the narrowed port set ───────
    print(f"[active_probe] Stage 2: nmap analysis ({nmap_arguments}) ...")
    try:
        scanner.scan(hosts=target_ip, arguments=nmap_arguments)
    except Exception as e:
        raise RuntimeError(f"nmap scan failed: {e}")

    if target_ip not in scanner.all_hosts():
        raise RuntimeError(
            f"nmap returned no results for {target_ip}. "
            "Host may be down or fully firewalled."
        )

    host = scanner[target_ip]
    print(f"[active_probe] Host state: {host.state()}")

    # ── active_os_probe evidence ──────────────────────────────────────────
    os_matches = host.get("osmatch", [])
    if os_matches:
        top         = os_matches[0]
        top_name    = top.get("name", "Unknown")
        top_acc     = int(top.get("accuracy", 0))
        top_conf    = round(top_acc / 100.0, 4)
        os_raw      = [
            {"name": m.get("name"), "accuracy": m.get("accuracy")}
            for m in os_matches[:10]
        ]
        matched_sig = top_name
        match_conf  = top_conf
        print(f"[active_probe] OS: {top_name} (accuracy {top_acc}%)")
    else:
        os_raw      = []
        matched_sig = None
        match_conf  = None
        print("[active_probe] No OS match returned by nmap.")

    add_evidence(
        mac_address=mac,
        signal_type="active_os_probe",
        raw_data={"os_matches": os_raw, "ip_address": target_ip, "discovery_method": discovery_method},
        matched_signature=matched_sig,
        match_confidence=match_conf,
        source=source_tag,
    )

    # ── active_port_scan evidence (service/version detail from nmap) ───────
    ports_info: dict = {}
    best_type: str | None = None
    best_conf: float = 0.0

    for port_str, port_data in host.get("tcp", {}).items():
        port = int(port_str)
        if port_data.get("state") != "open":
            continue
        ports_info[port] = {
            "service": port_data.get("name", ""),
            "product": port_data.get("product", ""),
            "version": port_data.get("version", ""),
        }
        if port in PORT_TYPE_HINTS:
            hint_type, hint_conf = PORT_TYPE_HINTS[port]
            if hint_conf > best_conf:
                best_type = hint_type
                best_conf = hint_conf

    if ports_info:
        print(f"[active_probe] Open ports (with service detail): {sorted(ports_info.keys())}")
    else:
        print("[active_probe] No open TCP ports confirmed by nmap.")

    if best_type:
        print(f"[active_probe] Device type from ports: {best_type} ({best_conf:.0%})")

    add_evidence(
        mac_address=mac,
        signal_type="active_port_scan",
        raw_data={"open_ports": ports_info, "ip_address": target_ip},
        matched_signature=best_type,
        match_confidence=best_conf if best_type else None,
        source=source_tag,
    )

    refreshed = get_device_by_mac(mac)
    print(f"[active_probe] Device row updated. OS family: {refreshed.inferred_os_family}")
    return refreshed


# ── CLI entry point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Active OS + service probe (on-demand only -- one device at a time)."
    )
    parser.add_argument("--mac", required=True, help="Target device MAC address")
    args = parser.parse_args()

    try:
        device = probe_device(args.mac)
        print()
        print("=" * 60)
        print("Updated device record:")
        print(f"  MAC          : {device.mac_address}")
        print(f"  Hostname     : {device.hostname}")
        print(f"  OS Family    : {device.inferred_os_family} ({device.confidence_os_family:.0%})")
        print(f"  Device Type  : {device.inferred_device_type} ({device.confidence_device_type:.0%})")
        print(f"  Manufacturer : {device.inferred_manufacturer}")
        print("=" * 60)
    except (ValueError, RuntimeError) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()