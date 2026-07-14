from scapy.all import sniff, Ether, IP, TCP


recognized_mac = {
    'b8:8a:60:7f:a6:16' : 'Linux Mint',     #my linux laptop 
    '24:11:53:0d:de:5e' : 'Samsung A34'     #my samsung A34's own mac address
}

interface = 'wlp2s0'
def packet_callback():
    pass

def main():
    print("Starting packet sniffing...")
    sniff(iface=interface , prn=packet_callback, filter="tcp", store=0, timeout=4)
    print("Packet sniffing finished or timed out.")

if __name__ == "__main__": 
    main()