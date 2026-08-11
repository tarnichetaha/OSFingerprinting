from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Evidence:
    evidence_id:        str
    mac_address:        str
    signal_type:        str          # 'dhcp' | 'tcp_ip' | 'tls_ja3' | 'mdns' | 'ssdp' | 'netbios'
    raw_data:           dict
    matched_signature:  Optional[str] = None
    match_confidence:   Optional[float] = None
    observed_at:        Optional[datetime] = None


@dataclass
class Device:
    mac_address:        str
    mac_oui:            Optional[str] = None
    vendor_name:        str = "Not Recorded"
    hostname:           str = "Not Recorded"
    first_seen:         Optional[datetime] = None
    last_seen:          Optional[datetime] = None
    ip_address_current: Optional[str] = None

    inferred_os_family:    str = "Not Recorded"
    inferred_os_version:   str = "Not Recorded"
    inferred_device_type:  str = "Not Recorded"
    inferred_manufacturer: str = "Not Recorded"
    inferred_model:        str = "Not Recorded"

    confidence_os_family:    float = 0.0
    confidence_os_version:   float = 0.0
    confidence_device_type:  float = 0.0

    # which PCAP file or live interface first produced this device
    source: Optional[str] = None

    # not a DB column — populated on demand by get_device_by_mac / get_evidence_for_device
    evidence: list = field(default_factory=list)