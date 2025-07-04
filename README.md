# Intern_Security_655
Attack Defense Scripts for Local DNS Spoofing Attack

#Based on Seed Security Labs - Local DNS Attacks

I was assigned as a grad student to lead a group project and demonstrate and attack defense strategy for DNS Spoonging 

The first stage is to setup a baseline attack :

Pre-Stage:

*Create a test environment to test the codes (done using a virtual machines and spawning a local docker network to test on)   
*Familiarization with DNS, local DNS spoofing attack, and its countermeasures.

Stage 1: 

@Attackers:

Deploy Local DNS Spoofing attack by replying to the user by a forged DNS reply before the DNS server response reaches him.
Thus the Local DNS reply will be discarded. (Successful)

@Detectors:

Detect Local DNS spoofing targeting the user packet by looking for multiple replies with different answers on the same query. 

Stage 2:

@Attackers: 
Evade detectv1 using a stream of carefully spoofed DNS queries packet to bypass the user detection technique.

@Detectors:
Detect attackv2 using resource<->ip dictionary indexing (stream analysis)  
  
Stage 3:  
  
@Attacker:  
Target the Local DNS cache, complicating things to the detectors.  
