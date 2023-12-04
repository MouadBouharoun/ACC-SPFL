from scapy.all import *
import csv

# Function to handle captured packets
def packet_handler(packet):
    if IP in packet:  # Check if the packet is an IP packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
        in_bytes = len(packet)
        # label the packet
        label = "enumeration"

        # Append the extracted fields and label to the existing CSV file
        with open('/home/mouad/federated_learning_demo/apache_data.csv', 'a', newline='') as csvfile:
            fieldnames = ['Source IP', 'Destination IP', 'Protocol', 'TTL', 'IN BYTES', 'Label']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'Source IP': src_ip, 'Destination IP': dst_ip, 'Protocol': protocol, 'TTL': ttl, 'IN BYTES': in_bytes, 'Label': label})

# Sniff network traffic and invoke the packet_handler function for each captured packet
sniff(prn=packet_handler, count=20000, iface='docker0')  # Capture 20000 packets as an example
