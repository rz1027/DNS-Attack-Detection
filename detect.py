from scapy.all import IP,DNS, sniff, DNSQR, sr1
import sys

try :
    interface = input ("[*] Enter desired Interface : ")
except:
    KeyboardInterrupt
    print("[*]User Requested Shutdown")
    print("[*]Exiting...")
    sys.exit(1)

def querysnif(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            print (str(ip_src) + " | " + repr(pkt[DNSQR]) + " | " + " --------------> " + str(ip_dst) + " : " + "(" + str(pkt.getlayer(DNS).qd.qname) + ")") 
        print("-->",pkt[DNS].summary())

sniff(iface = interface,filter = "UDP” ,prn = querysnif, store=0)
