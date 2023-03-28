from scapy.all import *


def start_capture(interface_name):
    interface_object = conf.route.addrs[interface_name]


def packet_handler(packet):
    print(packet.summary())


sniff(iface="en0", prn=packet_handler)
