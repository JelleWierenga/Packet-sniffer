from scapy.all import *
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

df = pd.DataFrame(columns=["Packet No.", "Type", "Source", "Destination", "Protocol"])

Amount = int(input("Enter the amount of packets you want to sniff: "))

packets = sniff(count=Amount)

question = input("Do you wish to see the packet info for a specific packet or all of them? (specific/all): ")

if question == "specific":
    number = int(input("Enter the number of the packet you want to see: "))
    if number < Amount:
        if packets[number].haslayer(IP):
            print("IP packet")
            source = packets[number][IP].src
            destination = packets[number][IP].dst
            type = packets[number][Ether].type
            proto = packets[number][IP].proto
            print(f"""
            IP packet details:
            Source IP: {source}
            Destination IP: {destination}
            Protocol: {"TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else f"Unknown protocol ({proto})"))}
            Type: {"IPv4" if type == 0x800 else "IPv6"}
            """)
        elif packets[number].haslayer(ARP):
            print("ARP packet")
            source = packets[number][ARP].psrc
            destination = packets[number][ARP].pdst
            type = packets[number][Ether].type
            print(f"""
            ARP packet details:
            Source IP: {source}
            Destination IP: {destination}
            Type: {"IPv4" if type == 0x800 else "IPv6"}
            """)
        else:
            print("Not an IP or ARP packet")

elif question == "all":
    question = input(
        f"Do you wish to see all the {Amount} packets in the CLI or in a file or database? (CLI/database): ")
    if question == "CLI":
        for i in range(Amount):
            if packets[i].haslayer(IP):
                print(f"{i}. IP packet")
                source = packets[i][IP].src
                destination = packets[i][IP].dst
                type = packets[i][Ether].type
                proto = packets[i][IP].proto
                print(f"""
                IP packet details:
                Source IP: {source}
                Destination IP: {destination}
                Protocol: {"TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else f"Unknown protocol ({proto})"))}
                Type: {"IPv4" if type == 0x800 else "IPv6"}
                """)
            elif packets[i].haslayer(ARP):
                print(f"{i}. ARP packet")
                source = packets[i][ARP].psrc
                destination = packets[i][ARP].pdst
                type = packets[i][Ether].type
                print(f"""
                ARP packet details:
                Source IP: {source}
                Destination IP: {destination}
                Type: {"IPv4" if type == 0x800 else "IPv6"}
                """)
            else:
                print(f"{i}. Not an IP or ARP packet")
    elif question == "database":
        for i in range(Amount):
            if packets[i].haslayer(IP):
                source = packets[i][IP].src
                destination = packets[i][IP].dst
                type = packets[i][Ether].type
                proto = packets[i][IP].proto
                df.loc[len(df.index)] = [f"packet {i}", "IP", source, destination, "TCP" if proto == 6 else (
                    "UDP" if proto == 17 else ("ICMP" if proto == 1 else f"Unknown protocol ({proto})"))]
            elif packets[i].haslayer(ARP):
                source = packets[i][ARP].psrc
                destination = packets[i][ARP].pdst
                df.loc[len(df.index)] = [f"packet {i}", "ARP", source, destination, "ARP"]
            else:
                df.loc[len(df.index)] = [f"Unknown packet {i}", "Unknown", "Unknown", "Unknown", "Unknown"]

        fileName = input("Enter the name of the file you want to save the packet details in: ")
        print("Saving the packet details in a file...")
        df.to_excel(f"{fileName}.xlsx", index=False)
        print("Packet details saved successfully!")

        if not df.empty:
            G = nx.from_pandas_edgelist(df[df['Source'] != "Unknown"], "Source", "Destination", edge_attr=["Protocol"])

            plt.figure(figsize=(10, 7))
            pos = nx.spring_layout(G)
            nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=2000, edge_color='k', font_size=10)
            labels = nx.get_edge_attributes(G, 'Protocol')
            nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
            plt.show()
