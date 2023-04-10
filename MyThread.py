import sys
from PyQt6.QtWidgets import QApplication, QWidget, QTableWidget
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from scapy.all import *

class MyThread(QThread):
    finished = pyqtSignal()

    def __init__(self, table_widget = QTableWidget(), interface_name = 'en0'):
        super().__init__()
        self.table_widget = table_widget
        self.interface_name = interface_name

    def run(self):
        self.packets_list = sniff(iface = self.interface_name, count = 5, prn = self.update)
        self.finished.emit()

    def update(self, packet):

        while packet.payload != 0:
            src_str = packet.src + "/"
            dst_str = packet.dst + "/"
            packet = packet.payload
        self.table_widget.insertRow(-1)