from PyQt6 import QtCore
from PyQt6.QtWidgets import QTableWidgetItem
from scapy.all import *

class MyThread(QtCore.QThread):
    task_finished = QtCore.pyqtSignal(str)

    def run(self):
        packets_list = sniff(iface = 'en0', prn = self.packet_callback, count = 50)

    def packet_callback(self, packet):
        self.task_finished.emit(str(packet.summary()))
