from scapy.all import *

packets = sniff(count=1)
# packets.summary()
# packets[0].show()

if packets[0].haslayer(IP):
    print("IP packet")
    source = packets[0][IP].src
    destination = packets[0][IP].dst
    type = packets[0][Ether].type
    proto = packets[0][IP].proto
    print(f"""
    IP packet details:
    Source IP: {source}
    Destination IP: {destination}
    Protocol: {"TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else f"Unknown protocol ({proto})"))}
    Type: {"IPv4" if type == 0x800 else "IPv6"}
    
    """)
elif packets[0].haslayer(ARP):
    print("ARP packet")
    source = packets[0][ARP].psrc
    destination = packets[0][ARP].pdst
    type = packets[0][Ether].type
    print(f"""
    ARP packet details:
    Source IP: {source}
    Destination IP: {destination}
    Type: {"IPv4" if type == 0x800 else "IPv6"}
    """)
else:
    print("Not an IP or ARP packet")