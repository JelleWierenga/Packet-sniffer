from scapy.all import *
packets = sniff(count=1)
packets.summary()
packets[0].show()