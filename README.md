# Intern_Security_655
Attack Defense Scripts for Local DNS Spoofing Attack

Hello Guys , this is the assignment repo.

The first stage is to setup a baseline attack :

Stage 1:

*Create a test environment to test the codes (done using a virtual machines and spawning a local docker network to test on)
*Familiarization with DNS, local DNS spoofing attack, and its countermeasures.

Stage 2: 

@Attackers:

Deploy Local DNS Spoofing attack by replying to the user by a forged DNS reply before the DNS server response reaches him.
Thus the Local DNS reply will be discarded. (Successful)

@Detectors:

Detect Local DNS spoofing targeting the user packet by looking for multiple replies with different answers on the same query. 

Stage 3:

@Attackers: 


@Detectors:
