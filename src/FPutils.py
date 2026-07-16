import os
import requests
from config import URL, API_KEY, SCORE_THRESHOLD, DEBUG


LOGS_DIR = 'logs'


def ensure_logs_dir():
    #create logs folder if doesnt exist
    os.makedirs(LOGS_DIR, exist_ok=True)


"""
    functions that i've used to analyse specific packet layers/ layer items to determine device info
"""
def get_device_info_from_fingerbank(op55, op60, mac):  
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'dhcp_fingerprint': op55,
        'dhcp_vendor' : op60,
        'mac' : mac
    }

    try :
        response = requests.post(URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        if DEBUG:
            ensure_logs_dir()
            with open('logs/api_reponses.log', 'a') as file:
                file.write('='*150)
                for k, v in data.items():
                    file.write('\n')
                    file.write(f'{k} : {v}')

        return data['device']['name'], data['score']
    except requests.RequestException as e:
        if DEBUG :
            print("✖"*100)
            print(f"Fingerbank request failed : {e}")
            if e.response is not None:
                print("Status:", e.response.status_code)
                print("Body:", e.response.text)
            print("✖"*100)
        
    
    return None, None


def is_randomized_mac(mac_address):
    # Check if the MAC adress is randomized based on the second least significant bit of the first byte
    first_byte = int(mac_address.split(':')[0], 16)
    # if 7th bit of 1st byte (left to right) = 1  : randomized MAC address
    return (first_byte & 0b00000010) != 0

def parse_http_user_agent(payload, device):
    #rxtract User-Agent from HTTP traffic for OS/hostname hints.
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        if 'HTTP' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
            for line in payload_str.split('\r\n'):
                if line.lower().startswith('user-agent:'):
                    ua = line[12:].strip()
                    device.http_user_agent = ua
                    device.ev_http_user_agent = f"HTTP_UA:{ua[:80]}"
                    return True
    except Exception:
        pass
    return False


def get_device_info_from_dhcp_opt(dhcp_layer, device):
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
    
    #op60 block — FIXED: was incorrectly writing to op55
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'vendor_class_id':
            op60 = str(option[1])
            break
        
    if op55 or op60 or mac:
        #API 
        print(f"Attempting API request for dhcp_fingerprint: op55={op55}, op60={op60}")

        os, score = get_device_info_from_fingerbank(op55, op60, mac)

        if not(os):
            return
        
        # If score is below threshold, retry without MAC address
        if score is not None and score < SCORE_THRESHOLD and mac is not None:
            print(f"Score {score} below threshold {SCORE_THRESHOLD}, retrying without MAC")
            os, score = get_device_info_from_fingerbank(op55, op60, None)
        
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
    if DEBUG:
        print(f"\nLooking for hostname in DHCP options for device with MAC: {device.mac_address}")
        print(f"DHCP Options: {dhcp_layer.options}")
    hostname = None
    device.ev_hostname = "No evidence found in DHCP options"
    for option in dhcp_layer.options:
        if isinstance(option, tuple) and option[0] == 'hostname':
            if DEBUG:
                print(f"Found hostname in DHCP options: {option[1].decode('utf-8')}")
            hostname = option[1].decode('utf-8')
            break
    
    if hostname:
        if DEBUG:
            print(f"Setting hostname for device with MAC: {device.mac_address} to: {hostname}")
        device.hostname = hostname
        device.ev_hostname = f"DHCP_op12:hostname={hostname}"

def get_os_from_ttl(ttl, device):
    if ttl <= 64:
        device.os_ttl = 'Linux'
        device.ev_os_ttl = ttl
    elif ttl <= 128:
        device.os_ttl = 'Windows'
        device.ev_os_ttl = ttl
    else:
        device.os_ttl = 'Network Gear'
        device.ev_os_ttl = ttl   
