import sys
import threading
from MainWindow import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow, QApplication, QTableWidgetItem, QMessageBox, QAbstractItemView, QTreeWidgetItem
from ipconfig import get_interfaces_name
from scapy.all import *

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *

# 捕获的报文列表
packet_list = []
# 捕获的报文总数
packet_count = 0

thread_stop = threading.Event()
thread_pause = threading.Event()


class SnifferWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.display_interfaces_list()
        self.show()

        # 初始化captured_view窗口
        # self.captured_view.setEditTriggers(QAbstractItemView.)
        self.captured_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.captured_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        # 连接信号槽函数
        self.sniff_button.clicked.connect(self.sniff_button_logic)
        self.pause_button.clicked.connect(self.pause_button_logic)
        self.stop_button.clicked.connect(self.stop_button_logic)
        self.captured_view.itemClicked.connect(self.display_current_packet)
        # self.resniff_button.clicked.connect(self.resniff_button_logic)

    def set_captured_view_header(self):
        self.captured_view.setVerticalHeader()

    # 下拉框添加网卡
    def display_interfaces_list(self):
        interifaces_list = get_interfaces_name()
        self.interfaces_combo.addItems(interifaces_list)


    def sniff_packet(self):
        global thread_stop
        sniff(prn=self.add_packet, iface=self.interfaces_combo.currentText(),
              stop_filter=lambda pkt: thread_stop.is_set())

    # 数据包展示
    def add_packet(self, packet):
        global packet_list
        global packet_count
        if not thread_pause.is_set():
            packet_list.append(packet)
            packet_count += 1

            protocal_list = ['ICMPv6', 'HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'DHCP', 'DHCP6', 'IPv6', 'IP', 'ARP', 'Ether', 'Unknown']
            protocal_name = ''

            source = ''
            destination = ''

            for pn in protocal_list:
                if pn in packet:
                    protocal_name = pn
                    break
            if protocal_name == 'ARP' or protocal_name == 'Ether':
                source = packet.src
                destination = packet.dst
            else:
                if 'IPv6' in packet:
                    source = packet[IPv6].src
                    destination = packet[IPv6].dst
                elif 'IP' in packet:
                    source = packet[IP].src
                    destination = packet[IP].dst
            length = str(len(packet))
            info = packet.summary()

            # 更新抓包窗口
            print(sniffer.captured_view.rowCount())
            row = sniffer.captured_view.rowCount()
            sniffer.captured_view.insertRow(row)
            sniffer.captured_view.setItem(row, 0, QTableWidgetItem(str(packet_count)))
            sniffer.captured_view.setItem(row, 1, QTableWidgetItem(str(packet.time)))
            sniffer.captured_view.setItem(row, 2, QTableWidgetItem(source))
            sniffer.captured_view.setItem(row, 3, QTableWidgetItem(destination))
            sniffer.captured_view.setItem(row, 4, QTableWidgetItem(protocal_name))
            sniffer.captured_view.setItem(row, 5, QTableWidgetItem(length))
            sniffer.captured_view.setItem(row, 6, QTableWidgetItem(info))

    def display_current_packet(self):
        global packet_list
        row = self.captured_view.currentRow()
        packet = packet_list[row]

        # 展示窗口初始化
        self.treeWidget.clear()
        self.hex_browser.clear()

        # 在hex窗口显示二进制报文信息
        self.hex_browser.setText(hexdump(packet, dump=True))

        # 在树形窗口按照层次展示报文
        lines = (packet.show(dump=True)).split('\n')
        current_level = 0
        current_item = None
        for line in lines:
            if line.startswith('#'):
                if current_level == 0:
                    root = QTreeWidgetItem(self.treeWidget)
                    root.setText(0, line)
                    self.treeWidget.addTopLevelItem(root)
                    current_level += 1
                    current_item = root
                else:
                    item = QTreeWidgetItem(self.treeWidget.topLevelItem(current_level))
                    item.setText(0, line)
                    self.treeWidget.addTopLevelItem(item)
                    current_level += 1
                    current_item = item
            elif '|#' in line:
                item = QTreeWidgetItem()
                item.setText(0, line)
                current_item.addChild(item)
            else:
                child = QTreeWidgetItem()
                child.setText(0, line)
                self.treeWidget.topLevelItem(current_level-1).addChild(child)

    # 开始嗅探按钮的逻辑
    def sniff_button_logic(self):
        global packet_list
        global packet_count

        # 如果包的数量不为0，那么开始前询问是否保存

        # 如果之前的抓包线程终止,将所有状态初始化
        if thread_stop.is_set():
            packet_list.clear()
            packet_count = 0
            thread_stop.clear()
            thread_pause.clear()
            self.captured_view.setRowCount(0)
            self.treeWidget.clear()
            self.hex_browser.clear()
        else:
            packet_list.clear()
            packet_count = 0
        # 开启抓包线程
        try:
            sniff_thread = threading.Thread(target=self.sniff_packet)
            sniff_thread.start()
        except:
            self.sniff_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.pause_button.setEnabled(False)
            QMessageBox.about(self, "消息提示框", "开启监听失败")
        # 改变按钮状态
        self.sniff_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.pause_button.setEnabled(True)


    # # 暂停按钮的逻辑
    def pause_button_logic(self):
        global thread_pause
        # 如果当前按钮状态为暂停的话
        if self.pause_button.text() == '暂停':
            thread_pause.set()
            self.pause_button.setText('继续')

        # 如果当前按钮状态为继续的话
        elif self.pause_button.text() == '继续':
            thread_pause.clear()
            self.pause_button.setText('暂停')

    # 停止按钮的逻辑
    def stop_button_logic(self):
        global thread_stop
        thread_stop.set()
        self.stop_button.setEnabled(False)
        self.sniff_button.setEnabled(True)
        self.pause_button.setEnabled(False)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = SnifferWindow()
    sys.exit(app.exec())
