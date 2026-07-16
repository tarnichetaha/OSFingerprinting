""" 
    Parse PCAP files for OS fingerprinting

    this code has one main function parse_pcap that :
        - reads through a pcap file (defined in config.py)
        - caches devices on ram for less reundant DB calls
        - calls functions from FPutils.py for analysis
        - updates database on batches of 100 during the loop, or leftovers after
"""

from scapy.all import PcapReader, Ether, IP, TCP, DHCP, Raw
from dbutils import *
from FPutils import *
import models
import time
import re

PCAP_FILE = 'house_dump-1.pcap'
PCAP_PATH = 'pcaps/' + PCAP_FILE


def parse_pcap():
    it1             = 0
    skipped_counter = 0

    cached_devices = {}
    batch_db_update = []
    BATCH_SIZE = 100
    
    start_time = time.perf_counter()
    with PcapReader(PCAP_PATH) as packets:
        for packet in packets:
            changes = False
            it1 += 1
            if it1 >= 200000:
                break
       
            if not(packet.haslayer(Ether) and packet.haslayer(IP)):
                continue
            
            device_mac = packet[Ether].src          
            
            # Check DEVICE exists in cache
            if device_mac not in cached_devices:
                # check if its a randomized or universal mac
                device = get_device_by_mac(PCAP_FILE, device_mac)
                if(device == None):
                    device = Device(mac_address=device_mac)
                    device.is_randomized_mac = is_randomized_mac(device_mac)         
                    changes = True
                
                cached_devices[device_mac] = device
            else :
                device = cached_devices[device_mac]

            if(packet.haslayer(TCP)):
                if packet[TCP].flags != 'S' and packet[TCP].flags != 'SA':          
                    #predict device based on TTL
                    #track the highest TTL seen (closest to original hop count)
                    if(device.os_ttl is None or int(device.ev_os_ttl) < packet[IP].ttl):
                        get_os_from_ttl(packet[IP].ttl, device)
                        changes = True

                # HTTP User-Agent parsing (non-SYN packets with payload)
                if packet.haslayer(Raw):
                    raw_payload = packet[Raw].load
                    if parse_http_user_agent(raw_payload, device):
                        changes = True
            
            if(packet.haslayer(DHCP)):      
                #fetch hostname (sometimes doesnt exist)
                if(device.hostname is None):
                    get_hostname_from_dhcp(packet[DHCP], device)
                    changes = True
                
                # will call api request
                if(device.os_opt55 is None or device.vendor_identity is None):
                    get_device_info_from_dhcp_opt(packet[DHCP], device)
                    changes = True
                
            if(changes):
                #update db when X amount of  updates are pending
                batch_db_update.append(device)
                if len(batch_db_update) >= BATCH_SIZE:
                    add_device_batch(PCAP_FILE, batch_db_update)
                    batch_db_update.clear()
        
        # update leftovers 
        if len(batch_db_update) > 0:
            add_device_batch(PCAP_FILE, batch_db_update)
            batch_db_update.clear()

            
    end_time = time.perf_counter()
    print('*'*150)
    print(f"Finished parsing packets. {it1 - skipped_counter} packets processed out of {it1}")
    elapsed_time = end_time - start_time
    print(f"Executed in: {elapsed_time:.4f} seconds")
            
    
def main():
    parse_pcap()

if __name__ == "__main__":
    main()