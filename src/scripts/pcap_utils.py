import os
import math
import pandas as pd
from typing import List, Dict, Any, Tuple
from scapy.all import PcapReader, PcapNgReader, Ether, IP, TCP


def round_ttl(ttl: int) -> int:
    """
    Rounds TTL value to the nearest higher power of two (32, 64, 128, 256).
    
    Examples:
        54 -> 64
        64 -> 64
        118 -> 128
        128 -> 128
        240 -> 256
    """
    if ttl <= 0:
        return 64
    if ttl <= 32:
        return 32
    elif ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 256


def extract_mss_from_tcp_options(tcp_layer: TCP) -> int:
    """
    Extracts Maximum Segment Size (MSS) from TCP layer options.
    Returns 0 if MSS option is not present.
    """
    if not tcp_layer.options:
        return 0
    
    for option in tcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'MSS':
            val = option[1]
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0
    return 0


def parse_syn_packets_from_pcap(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Parses a PCAP or PCAPNG file and extracts TCP SYN packets (flags == 'S', not SYN-ACK).
    Extracts MAC address, IP flow tuple, and the 5 OS fingerprinting features:
    - SRC_PORT
    - TCP_SYN_SIZE (IP layer total length)
    - TCP_WIN
    - TCP_MSS
    - TTL (power-of-two rounded)
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP/PCAPNG file not found: {pcap_path}")

    records = []
    try:
        reader = PcapReader(pcap_path)
    except Exception:
        reader = PcapNgReader(pcap_path)

    with reader:
        for pkt in reader:
            if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            
            tcp = pkt[TCP]
            # Match SYN packets (SYN bit set, ACK bit not set)
            if (int(tcp.flags) & 0x12) != 0x02:
                continue

            mac = str(pkt[Ether].src).lower()
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            
            # Extract 5 features
            tcp_syn_size = len(pkt[IP])  # Total IP packet length
            tcp_win = int(tcp.window)
            tcp_mss = extract_mss_from_tcp_options(tcp)
            raw_ttl = int(pkt[IP].ttl)
            ttl_rounded = round_ttl(raw_ttl)
            
            flow_key = (src_ip, src_port, dst_ip, dst_port)

            records.append({
                "mac_address": mac,
                "flow_key": flow_key,
                "SRC_PORT": src_port,
                "TCP_SYN_SIZE": tcp_syn_size,
                "TCP_WIN": tcp_win,
                "TCP_MSS": tcp_mss,
                "TTL": ttl_rounded,
                "raw_ttl": raw_ttl,
            })
            
    return records
