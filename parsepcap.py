

""" 
    Parse PCAP files for OS fingerprinting
"""

from scapy.all import PcapReader, rdpcap, Ether, IP, TCP
from listening import parse_packet

def parse_pcap():
    it1             = 0
    skipped_counter = 0
    linux_counter   = 0
    windows_counter = 0
    unknown_counter = 0

    unique_macs = set()
    
    with PcapReader('capture.pcap') as packets, open('output.txt', 'w') as output_file:
        for packet in packets:
            it1 += 1
            if it1 >= 10000:
                break

            if not (packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP)):
                continue
            
                #only Syn and Syn-Ack packets 3ndhom options [];
                
            if packet[TCP].flags != 'S' and packet[TCP].flags != 'SA' and packet[TCP].flags != 'A': 
                skipped_counter += 1
                continue

            if packet[IP].ttl <= 64:
                print(f"Packet {it1}: (Most likely: Linux/Android/iOS)")
                linux_counter += 1
            elif packet[IP].ttl <= 128:
                print(f"Packet {it1}: (Most likely: Windows)")
                windows_counter += 1
            else:
                print(f"Packet {it1}: (Most likely: Unknown OS/Cisco IOS Device)")
                unknown_counter += 1

            #print packet for now
            # parse_packet(packet[TCP], packet[IP])
            packet.show()
            unique_macs.add(packet[Ether].src)

            
    
    print(f"Finished parsing packets. {it1 - skipped_counter} packets processed out of {it1}")
    print(f"Linux/Android/iOS packets: {linux_counter}"
          f"\nWindows packets: {windows_counter}"
          f"\nUnknown OS/Cisco IOS packets: {unknown_counter}"
          f"\nUnique MAC addresses: {len(unique_macs)}")
            
    
def main():
    parse_pcap()

if __name__ == "__main__":
    main()