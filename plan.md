Progress in which i will be writing my code :




Capture packets passively -- (scapy), but how? and maybe i should filter my own PC and phone's mac address starting here

[x] = applied
[ ] = not applied

[x] Aside from SYN-SYNACK TCP packets used for detecting OS_family by reading ttl / options field ordering,  which can be a little vague due to some OS having linux based kernels 

[x] You can directly tell what kind of configuration the application is asking for by observing DHCP pakcets during IP assignment 
DHCP Option 12: The client explicitly sends its hostname to the DHCP server during address assignment, which often gives away the machine name.

[ ] Vendor Identity: The first three bytes of a MAC address are the Organizationally Unique Identifier (OUI).



================================================================
table_name is dynamically set based on pcap filename
db : 
table_name : [
	@MAC (id)	
	hostname
	net_config	
	os
	vendor_identity
	evidence_id
	last_seen
    ev_hostname
    ev_net_config      
    ev_os
    ev_vendor_identity
]
]

evidence: [ 
	id_evidence               
 
================================================================


