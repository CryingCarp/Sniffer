from PyQt6 import QtCore
from PyQt6.QtWidgets import QTableWidgetItem
from scapy.all import *

class MyThread(QtCore.QThread):
    task_finished = QtCore.pyqtSignal(int, str, str, str, str, str, str)

    def run(self):
        self.count = 0
        packets_list = sniff(iface = 'en0', prn = self.packet_callback, count = 1000)

    def packet_callback(self, packet):
        self.count += 1
        lastlayer = packet.lastlayer()
        self.task_finished.emit(self.count, str(lastlayer.time),
                                packet.src, packet.dst, lastlayer.name,
                                '2', '2')
