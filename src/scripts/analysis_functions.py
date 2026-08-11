import os
from config import ANALYSIS_DEBUG

SCAPY_TO_P0F_OPT = {
    'MSS': 'mss',
    'NOP': 'nop',
    'SAckOK': 'sok',
    'Timestamp': 'ts',
    'WScale': 'ws',
    'EOL': 'eol',
}



def is_randomized_mac(mac_address):
    first_byte = int(mac_address.split(':')[0], 16)
    return (first_byte & 0b00000010) != 0


def get_os_from_tcpip_sig(tcp_layer, ip_layer):

    
    
    if ANALYSIS_DEBUG :
        print(tcp_layer.show())
    # parse sig 
    
    # ver	IP version (4, 6, or * for either)	*
    # ittl	Initial TTL — the value before any hops decremented it	64
    # olen	IPv4 options length (almost always 0)	0
    # mss	Maximum Segment Size, or * if variable	*
    # wsize	Window size — can be a literal, an expression like mss*20, or %8192 (multiple-of)	mss*20,7
    # wscale	Window scaling factor (the ,7 above)	7
    # olayout	TCP options in the order the OS sends them — this is the single most identifying field	mss,sok,ts,nop,ws
    # quirks	Odd/distinguishing behaviors — df (don't-fragment set), id+/id- (IP ID zero or non-zero), ecn, seq-, etc.	df,id+
    # pclass	Payload class: 0 (SYN has no payload, normal), + (non-zero), * (either)	0

    tokens = []
    for opt in tcp_layer.options:
        name = opt[0]
        tokens.append(SCAPY_TO_P0F_OPT.get(name, name.lower()))
    return ",".join(tokens)


def parse_dhcp_options(dhcp_layer):
    """Extract op55/op60/hostname/ip from a DHCP layer. Pure parsing, no API call, no Device mutation."""
    op55 = None
    op60 = None
    hostname = None
    requested_ip = None

    if hasattr(dhcp_layer, 'ciaddr') and dhcp_layer.ciaddr and dhcp_layer.ciaddr != '0.0.0.0':
        requested_ip = str(dhcp_layer.ciaddr)
    elif hasattr(dhcp_layer, 'yiaddr') and dhcp_layer.yiaddr and dhcp_layer.yiaddr != '0.0.0.0':
        requested_ip = str(dhcp_layer.yiaddr)

    for option in dhcp_layer.options:
        if not isinstance(option, tuple):
            continue
        if option[0] == 'param_req_list':
            op55 = ",".join(map(str, option[1]))
        elif option[0] == 'vendor_class_id':
            op60 = str(option[1])
        elif option[0] == 'hostname':
            hostname = option[1].decode('utf-8', errors='ignore')
        elif option[0] == 'requested_addr':
            requested_ip = str(option[1])

    return {"option_55_param_list": op55, "option_60_vendor_class": op60, "hostname": hostname, "requested_ip": requested_ip}


def parse_http_user_agent(payload):
    """Extract User-Agent from raw HTTP payload bytes. Returns the UA string or None."""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        if 'HTTP' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
            for line in payload_str.split('\r\n'):
                if line.lower().startswith('user-agent:'):
                    return line[12:].strip()
    except Exception:
        pass
    return None