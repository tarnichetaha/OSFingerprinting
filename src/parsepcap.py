

""" 
    Parse PCAP files for OS fingerprinting
"""

from scapy.all import PcapReader, Ether, IP, TCP, DHCP
from dbutils import *
from fingerbank import get_device_info_from_fingerbank
import models
import time

PCAP_FILE = 'house_dump_1.pcap'
PCAP_PATH = 'pcaps/' + PCAP_FILE

def is_randomized_mac(mac_address):
    # Check if the MAC adress is randomized based on the second least significant bit of the first byte
    first_byte = int(mac_address.split(':')[0], 16)
    # if 7th bit of 1st byte = 1 : randomized MAC address
    return (first_byte & 0b00000010) != 0

def get_device_info_from_opt(dhcp_layer, device):
    #pass op55, op60
    op60 = None
    op55 = None
    mac = None
    if not(device.is_randomized_mac):
        mac = device.mac_address

    #op55 block
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'param_req_list':
            #format as "1,2,3,4" rather than [1, 2, 3 ,4] for fingerbank API
            op55 = ",".join(map(str, option[1]))
            break
    
    #op60 block
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'vendor_class_id':
            op55 = str(option[1])
            break
        
    if op55 or op60 or mac:
        #API 
        print(f"Attempting API request for dhcp_fingerprint : {op55}")

        os, score = get_device_info_from_fingerbank(op55, op60, mac)

        if not(os):
            return
        
        device.os_opt55 = os
        device.ev_os_opt55 = f"Fingerbank API: OS={os}"
        
        if (score):
           device.ev_os_opt55 += f", Score :{score}" 
        
        # if not(vendor or len(vendor) <= 0):
        #     device.vendor_identity = vendor
        #     device.ev_vendor_identity = f"Fingerbank API: Vendor={vendor}"

def get_hostname_from_dhcp(dhcp_layer, device):
    print(f"\nLooking for hostname in DHCP options for device with MAC: {device.mac_address}")
    print(f"DHCP Options: {dhcp_layer.options}")
    hostname = None
    device.ev_hostname = "No evidence found in DHCP options"
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'hostname':
            print(f"Found hostname in DHCP options: {option[1].decode('utf-8')}")
            hostname = option[1].decode('utf-8')
            break
    
    if hostname:
        print(f"Setting hostname for device with MAC: {device.mac_address} to: {hostname}")
        device.hostname = hostname
        device.ev_hostname = f"DHCP Option_12: Hostname={hostname}"

def get_os_from_packet(ttl, device):
    if ttl <= 64:
        device.os_ttl = 'Linux'
        device.ev_os_ttl = 'TCP/IP Packet TTL<=64)'
    elif ttl <= 128:
        device.os_ttl = 'Windows'
        device.ev_os_ttl = 'TCP/IP Packet TTL<=128)'
    else:
        device.os_ttl = 'Network Gear'
        device.ev_os_ttl = 'TCP/IP Packet TTL>128)'    

def parse_pcap():
    it1             = 0
    skipped_counter = 0

    
    start_time = time.perf_counter()
    with PcapReader(PCAP_PATH) as packets:
        for packet in packets:
            changes = False
            it1 += 1
            if it1 >= 20000:
                break

            
            if not(packet.haslayer(Ether) and packet.haslayer(IP)):
                continue
            
            device_mac = packet[Ether].src
            # target_mac = packet[Ether].dst            

            
            # Check DEVICE exists in db
            device = models.Device
            device = get_device_by_mac(PCAP_FILE, device_mac)
            if(device == None):
                # check if its a randomized or universal mac
                device = Device(mac_address=device_mac)
                device.is_randomized_mac = is_randomized_mac(device_mac)         
                
                changes = True

            if(packet.haslayer(TCP)):
                if packet[TCP].flags != 'S' and packet[TCP].flags != 'SA':          
                    # find TTL
                    if(device.os_ttl == None):
                        get_os_from_packet(packet[IP].ttl, device)
                        changes = True
            
            if(packet.haslayer(DHCP)):
                
                #fetch hostname (sometimes doesnt exist)
                if(device.hostname == None):
                    get_hostname_from_dhcp(packet[DHCP], device)
                    changes = True

                if(device.os_opt55 == None or device.vendor_identity == None):
                    get_device_info_from_opt(packet[DHCP], device)
                    changes = True
                
            if(changes):
                add_device_or_update(PCAP_FILE, device)

            
            
    end_time = time.perf_counter()
    print('*'*150)
    print(f"Finished parsing packets. {it1 - skipped_counter} packets processed out of {it1}")
    elapsed_time = end_time - start_time
    print(f"Executed in: {elapsed_time:.4f} seconds")
            
    
def main():
    parse_pcap()

if __name__ == "__main__":
    main()