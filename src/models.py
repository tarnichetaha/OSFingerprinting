class Device:
    def __init__(self, mac_address, is_randomized_mac=None, hostname=None, os_opt55=None, os_ttl=None, vendor_identity=None,
                ev_hostname=None, ev_os_opt55=None, ev_os_ttl=None, ev_vendor_identity=None,
                http_user_agent=None, ev_http_user_agent=None
                 ):
        
        self.mac_address    = mac_address
        self.is_randomized_mac = is_randomized_mac
        self.hostname       = hostname
        self.os_opt55       = os_opt55
        self.os_ttl         = os_ttl
        self.vendor_identity = vendor_identity
        self.ev_hostname    = ev_hostname
        self.ev_os_opt55    = ev_os_opt55
        self.ev_os_ttl      = ev_os_ttl
        self.ev_vendor_identity = ev_vendor_identity
        self.http_user_agent = http_user_agent
        self.ev_http_user_agent = ev_http_user_agent

    
    def __str__(self):
        return (
            f"MAC: {self.mac_address}\t(Randomized Mac : {self.is_randomized_mac} )\n"
            f"  Hostname: {self.hostname}\t(evidence: {self.ev_hostname})\n"
            f"  OS (Opt55):       {self.os_opt55}\t(evidence: {self.ev_os_opt55})\n"
            f"  OS (TTL):         {self.os_ttl}\t(evidence: {self.ev_os_ttl})\n"
            f"  Vendor:   {self.vendor_identity}\t(evidence: {self.ev_vendor_identity})\n"
            f"  HTTP UA: {self.http_user_agent}\t(evidence: {self.ev_http_user_agent})\n"
        )
