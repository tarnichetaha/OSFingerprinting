import argparse
from scapy.all import sniff, Ether, IP, TCP
from config import LIVE_IFACE


def packet_callback(packet):
    pass

def main():
    parser = argparse.ArgumentParser(description="Simple TCP sniff helper")
    parser.add_argument("--iface", default=LIVE_IFACE, help="Interface to sniff")
    args = parser.parse_args()

    print("Starting packet sniffing...")
    sniff(iface=args.iface, prn=packet_callback, filter="tcp", store=0, timeout=4)
    print("Packet sniffing finished or timed out.")

if __name__ == "__main__": 
    main()