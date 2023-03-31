from scapy.all import *


def is_ipv4(packet):
    if  type(packet) == scapy.layers.inet.IP:
        print("true")
        # print(packet.field.src)
        # print(packet.field.dst)
    else:
        print("false")

#在屏幕上打印输出数据包的二进制格式
def print_hex_on_monitor(packet):
    print(hexdump(packet))

#在display窗口打印输出

def sniff_all_packets(interface_name = 'en0'):
    return sniff(iface = interface_name, count = 5)

def print_on_monitor(packet):
    print(packet.summary())

packets_list = sniff_all_packets()
for packet in packets_list:
    print_hex_on_monitor(packet)
