#############################################################################
############################ DEFENSE STRATEGY V.2  ###########################

#############################################################################
############################### RYAN ALAM ###################################
# Import Scapy library to be used for sniffing packets
from scapy.all import DNS, sniff, DNSRR

# Import sys module to access useful functions and arguments
import sys
# Ask the user to enter the desired interface for sniffing
try :
    interface = input ("[*] Enter desired Interface : ")

# In case the user decided to quit, two display messages will quit illustrating that the user requested a shutdown and that it is exiting.
except:
    KeyboardInterrupt
    print("[*]User Requested Shutdown")
    print("[*]Exiting...")
    sys.exit(1)

#Creating a global packet queue
listq = []
ip = " "
packets =[]
# This function is to actually test the network for possible DNS attacks, specifically DNS spoofing.
def spoofTest(st, ip):

    # Cast the queue into a set. Then check for its length. If it's greater than one, this means
    # that there are two or more answers for the same query, which means there are multiple 
    # IP resolves for the same domain and eventually there is a DNS spoofing attack, so
    # a message is displayed to alert the user of that along with both resolves.
    S=set(listq)
    if len(S) > 1:
        website = ip.split("\"")
        print("Multiple Resolves For",website[1][2:-1]," Possible DNS Spoofing Detected !!!")
        for i,j in enumerate(S):
            print(i+1," :",j.split("\"")[1])



# The following function is for extracting the needed information for detection, mainly the DNS queries and responses.
def querysnif(pkt):
        global ip
        # This displays the information of the DNS packet. (Optional)
        print("-->",pkt[DNS].summary())

#############################################################################
######################### ABDEL RAHMAN AL LADIKI ############################

        # Cast the summary into a string.
        st=str(pkt[DNS].summary())

        # In this part, we are actually detecting the attack if existed. If the packet was a DNS query,
        # we enter the if statement and cas listq to a set. We confirm that it is an empty set for the
        # first packet; otherwise, there is a problem and we clear the list. After that, we add the DNS
        # responses to the list using the append method. Now, there is only one packet in the list,
        # meaning that listq is of length one containing the response of the first query. If this is 
        # not the case, then there are two replies sniffed for the same query and there is a possible 
        # DNS attack. However, spoofTest will be executed to detect the attack if existed.
        if st.startswith("DNS Qry"):
            ip=st
            listq.clear()
        else:
            listq.append(st)
            if len(listq)>1:
                spoofTest(st,ip)

#############################################################################
############################### RYAN ALAM ###################################

        if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
            for prev_pkt in packets:
                if prev_pkt[DNS].id == pkt[DNS].id and \
                                pkt[DNS].qd.qname == prev_pkt[DNS].qd.qname:

                    # Checking from the DNS query
                    # if its not spoofed, the responses should be the same if its not spoofed, otherwise, send a warning

                    rdata_pack = [pkt[DNS].an[i].rdata
                                    for i in range(pkt[DNS].ancount)
                                    if pkt[DNS].an[i].type == 1]

                    rdata_prev_pack = [prev_pkt[DNS].an[i].rdata
                                        for i in range(prev_pkt[DNS].ancount)
                                        if prev_pkt[DNS].an[i].type == 1]

                    intersection = set(rdata_pack).intersection(rdata_prev_pack)
                    # IP conflict, so we found a DNS spoofing attack !
                    if intersection == set([]):
                        print("!!!!!!!!!! Multiple Resolves For Same Website Possible DNS Spoofing Detected !!!!!!!!!!")
         
            # Add pkt to packets which is an array created Line 25
            packets.append(pkt)

# Execute the sniff function to actually sniff packets of the interface entered by the user.
# The filter is set to port 53 which is the port number of DNS
# prn argument refers to the function applied on each packet, which is querysnif in our case
# store argument is set to 0 to avoid storing all packets in the memory
sniff(iface = interface,filter = "port 53", prn = querysnif, store=0)

# This is to shut down the whole process
print("\n[*] Shutting Down...")
