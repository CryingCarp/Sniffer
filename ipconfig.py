import psutil

#获取当前网络所有网卡信息
#返回一个列表
def get_interfaces_name():
    net_if_addrs = psutil.net_if_addrs()
    interfaces_name = sorted(net_if_addrs.keys())
    return interfaces_name