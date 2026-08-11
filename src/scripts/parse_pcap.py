import os
import joblib
import pandas as pd
import numpy as np
from scapy.all import PcapReader, PcapNgReader, Ether, IP, TCP, DHCP, Raw
from database.db_utils import (
    add_evidence_batch, update_devices_from_evidence,
    register_source, update_source_stats,
)
from scripts.analysis_functions import get_os_from_tcpip_sig, parse_dhcp_options, parse_http_user_agent
import glob
from scripts.pcap_utils import extract_mss_from_tcp_options, round_ttl
from database.models import Evidence
import time
from config import DEFAULT_PCAP_PATH, PARSE_DEBUG, PCAPS_DIR, resolve_model_artifact_path


def parse_pcap(pcap_path: str = None, source: str | None = None):
    if not pcap_path:
        if DEFAULT_PCAP_PATH.exists():
            pcap_path = str(DEFAULT_PCAP_PATH)
        else:
            pcaps = sorted(glob.glob(str(PCAPS_DIR / "*.pcap")) + glob.glob(str(PCAPS_DIR / "*.pcapng")))
            if pcaps:
                pcap_path = pcaps[0]
            else:
                pcap_path = str(DEFAULT_PCAP_PATH)

    if source is None:
        source = os.path.basename(pcap_path)

    register_source(source, 'pcap')
    print(f"Parsing packet capture: '{pcap_path}'... (source='{source}')")
    it1 = 0
    # per-MAC "best seen so far" cache, purely to avoid redundant evidence rows
    best_ttl_seen = {}       # mac -> highest ttl seen (closest to original hop count)
    seen_http = set()        # one http UA evidence row per MAC per parse session

    evidence_batch = []
    touched_macs = set()
    BATCH_SIZE = 500
    stats_packets_flushed = 0

    # Load ML classifier model if present
    model_artifact_path = resolve_model_artifact_path()
    ml_model = None
    label_encoder = None
    expected_features = None
    if model_artifact_path.exists():
        try:
            artifact = joblib.load(model_artifact_path)
            ml_model = artifact["model"]
            label_encoder = artifact["label_encoder"]
            expected_features = artifact["feature_names"]
        except Exception as e:
            if PARSE_DEBUG:
                print(f"Warning: Could not load ML model artifact: {e}")

    start_time = time.perf_counter()
    try:
        reader = PcapReader(pcap_path)
    except Exception:
        reader = PcapNgReader(pcap_path)

    with reader as packets:
        for packet in packets:
            it1 += 1
            if it1 >= 200000:
                break

            if not (packet.haslayer(Ether) and packet.haslayer(IP)):
                continue

            mac = str(packet[Ether].src).lower()
            src_ip = str(packet[IP].src)

            if packet.haslayer(TCP):
                # Check for TCP SYN packet
                if (int(packet[TCP].flags) & 0x12) == 0x02:
                    ttl = int(packet[IP].ttl)
                    if mac not in best_ttl_seen or ttl > best_ttl_seen[mac]:
                        best_ttl_seen[mac] = ttl
                        sig = get_os_from_tcpip_sig(packet[TCP], packet[IP])
                        
                        src_port = int(packet[TCP].sport)
                        tcp_syn_size = len(packet[IP])
                        tcp_win = int(packet[TCP].window)
                        tcp_mss = extract_mss_from_tcp_options(packet[TCP])
                        ttl_rounded = round_ttl(ttl)

                        os_guess = None
                        match_conf = 0.8
                        if ml_model and label_encoder and expected_features:
                            df_feat = pd.DataFrame([{
                                "SRC_PORT": src_port,
                                "TCP_SYN_SIZE": tcp_syn_size,
                                "TCP_WIN": tcp_win,
                                "TCP_MSS": tcp_mss,
                                "TTL": ttl_rounded
                            }])[expected_features]
                            probas = ml_model.predict_proba(df_feat)
                            pred_idx = np.argmax(probas, axis=1)[0]
                            os_guess = str(label_encoder.inverse_transform([pred_idx])[0])
                            match_conf = float(np.max(probas, axis=1)[0])
                        else:
                            if ttl_rounded <= 64:
                                os_guess = "linux / android"
                            elif ttl_rounded <= 128:
                                os_guess = "windows"
                            else:
                                os_guess = "network gear"

                        raw_tcp = {
                            "ip_address": src_ip,
                            "src_port": src_port,
                            "tcp_syn_size": tcp_syn_size,
                            "tcp_win": tcp_win,
                            "tcp_mss": tcp_mss,
                            "ttl": ttl,
                            "sig": sig
                        }

                        evidence_batch.append(Evidence(
                            evidence_id=None, mac_address=mac, signal_type="tcp_ip",
                            raw_data=raw_tcp, matched_signature=os_guess,
                            match_confidence=match_conf, observed_at=None,
                        ))
                        touched_macs.add(mac)

                if packet.haslayer(Raw):
                    ua = parse_http_user_agent(packet[Raw].load)
                    if ua and mac not in seen_http:
                        evidence_batch.append(Evidence(
                            evidence_id=None, mac_address=mac, signal_type="http",
                            raw_data={"user_agent": ua, "ip_address": src_ip}, matched_signature=None,
                            match_confidence=None, observed_at=None,
                        ))
                        seen_http.add(mac)
                        touched_macs.add(mac)

            if packet.haslayer(DHCP):
                parsed = parse_dhcp_options(packet[DHCP])
                if parsed["option_55_param_list"] or parsed["option_60_vendor_class"] or parsed["hostname"]:
                    dhcp_ip = parsed.get("requested_ip") or src_ip
                    parsed["ip_address"] = dhcp_ip
                    evidence_batch.append(Evidence(
                        evidence_id=None, mac_address=mac, signal_type="dhcp",
                        raw_data=parsed, matched_signature=None,
                        match_confidence=None, observed_at=None,
                    ))
                    touched_macs.add(mac)

            if len(evidence_batch) >= BATCH_SIZE:
                add_evidence_batch(evidence_batch, source=source)
                packet_delta = it1 - stats_packets_flushed
                update_source_stats(source, packet_delta=packet_delta, evidence_delta=len(evidence_batch))
                stats_packets_flushed = it1
                update_devices_from_evidence(touched_macs, source=source)
                evidence_batch.clear()
                touched_macs.clear()

        if evidence_batch:
            add_evidence_batch(evidence_batch, source=source)
            packet_delta = it1 - stats_packets_flushed
            update_source_stats(source, packet_delta=packet_delta, evidence_delta=len(evidence_batch))
            stats_packets_flushed = it1
            if PARSE_DEBUG:
                print("Updating DB")
            update_devices_from_evidence(touched_macs, source=source)
        elif it1 > stats_packets_flushed:
            update_source_stats(source, packet_delta=(it1 - stats_packets_flushed), evidence_delta=0)

    elapsed = time.perf_counter() - start_time
    print('*' * 150)
    print(f"Finished parsing. {it1} packets processed")
    print(f"Executed in: {elapsed:.4f} seconds")


def main():
    parse_pcap()


if __name__ == "__main__":
    main()