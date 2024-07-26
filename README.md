Simple Network Packet Sniffer
This repository contains a simple network packet sniffer written in Python. The sniffer captures and analyzes Ethernet frames and IPv4 packets, including ICMP, TCP, and UDP segments.

Features
Captures raw network packets using Python's socket module.
Parses and displays Ethernet frame details.
Parses and displays IPv4 packet details.
Parses and displays ICMP, TCP, and UDP segment details.

Requirements
Python 3.x

Installation
To run this packet sniffer, ensure you have Python 3 installed on your system. No additional libraries are required.

How It Works
Ethernet Frame Parsing:

The ethernet_frame function extracts the destination MAC address, source MAC address, and protocol type from the Ethernet frame.
IPv4 Packet Parsing:

The ipv4_packet function extracts the version, header length, TTL, protocol, source IP, and destination IP from the IPv4 packet.
Protocol Handling:

The icmp_packet function parses ICMP packets.
The tcp_segment function parses TCP segments.
The udp_segment function parses UDP segments.

Main Loop:

The main function creates a raw socket and continuously captures packets. For each packet, it parses the Ethernet frame and, if applicable, the IPv4 packet and its payload.

Contributing
Feel free to open issues or submit pull requests with improvements or bug fixes.
