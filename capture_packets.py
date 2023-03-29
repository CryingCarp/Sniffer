from scapy.all import *


def start_capture(interface_name):
    interface_object = conf.route.addrs[interface_name]


def packet_handler(packet):
    print(packet.summary())

def sniff_all_packets(interface_name):
    sniff(iface = interface_name, prn = packet_handler)

