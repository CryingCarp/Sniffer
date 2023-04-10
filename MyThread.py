import sys
from PyQt6.QtWidgets import QApplication, QWidget, QTableWidget, QThread
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from capture_packets import sniff_all_packets

class MyThread(QThread):
    finished = pyqtSignal()

    def __init__(self, table_widget, interface_name = 'en0'):
        super().__init__()
        self.table_widget = table_widget
        self.interface_name = interface_name

    def run(self):
        self.packets_list = sniff_all_packets(self.interface_name, prn = self.update, count = 5)
        self.finished.emit()

    def update(self, packet):
        while packet.payload != 0:
            packet = packet.payload
        self.table_widget.add