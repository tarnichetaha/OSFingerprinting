import requests
from config import URL, API_KEY


def get_device_info_from_fingerbank(op55, op60, mac):  
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'dhcp_fingerprint': op55,
        'dhcp_vendor' : op60,
    }

    try :
        response = requests.post(URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        return data['device']['name'], data['score']
    except requests.RequestException as e:
        print("*"*100)
        print(f"Fingerbank request failed : {e}")
        if e.response is not None:
            print("Status:", e.response.status_code)
            print("Body:", e.response.text)
        
    
    return None, None
