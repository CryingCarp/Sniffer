from scapy.all import wrpcap, rdpcap
import os

current_path = os.getcwd()


# 判断文件是否存在
def is_file_exist(path=current_path, filename="untitled.pcap"):
    filepath = path + "/" + filename
    if os.path.exists(filepath):
        return True
    else:
        return False


# 保存单个数据包
def save_single_packet(packet, path=current_path, filename="untitled.pcap"):
    if wrpcap(path + "/" + filename, [packet]):
        return True
    else:
        return False


# 保存多个数据包
def save_multiple_packets(packets_list, path=current_path, filename="untitled.pcap"):
    if wrpcap(path + "/" + filename, packets_list):
        return True
    else:
        return False


# 读取新的pacp文件
def read_pacp_file(path, filename):
    if is_file_exist(path, filename):
        return rdpcap(path + "/" + filename)
    else:
        return False
