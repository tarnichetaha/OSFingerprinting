from scapy.all import sniff, Ether, IP, TCP
from dbutils import *

recognized_mac = {
    'b8:8a:60:7f:a6:16' : 'Linux Mint',     #my linux laptop 
    '24:11:53:0d:de:5e' : 'Samsung A34'     #my samsung A34's own mac address
}

interface = 'wlp2s0'

def parse_packet(tcp, ip):
    ver = ip.version
    observed_ttl = ip.ttl
    window_size = tcp.window
    options = dict(tcp.options)
    print(f"IP Version: {ver}")
    print(f"Flag : {tcp.flags}")
    print(f"Observed TTL: {observed_ttl}")
    print(f"Window Size: {window_size}")

    print(f"Options:[" )
    if('MSS' in options):
        print(f"\n\tMSS:{options['MSS']}")
    if('SAckOK' in options):
        print(f"\n\tSAckOK:{options['SAckOK']}")
    if('WScale' in options):
        print(f"\n\tWScale:{options['WScale']}")
    print("]")
    print('-'*50)

    

def packet_callback(packet):
    """ 
    Process sniffed packet, has to be an ethernet packet with IP and TCP layers
    MAC source address has to correspond to known addresses. (for cross-checking later)
    """
    #TCP packets dont always have Ethernet and IP Layers
    if not(packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    
    if packet[TCP].flags != 'S' and packet[TCP].flags != 'SA' and packet[TCP].flags != 'A': 
        return
    
    src_mac = packet[Ether].src
    if(src_mac in recognized_mac):
        print(f"Packet Received:\nSrc: {recognized_mac[src_mac]}")
        parse_packet(packet[TCP], packet[IP])


        
def main():
    print("Starting packet sniffing...")
    sniff(iface=interface , prn=packet_callback, filter="tcp", store=0)
    print("Packet sniffing finished or timed out.")


if __name__ == "__main__": 
    main()