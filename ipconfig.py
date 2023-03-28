import psutil


def get_interfaces_name():
    net_if_addrs = psutil.net_if_addrs()
    interfaces_name = sorted(net_if_addrs.keys())
    return interfaces_name

