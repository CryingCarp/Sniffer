import sys
from MainWindow import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow, QApplication, QAbstractItemView, QTableWidget, QTableWidgetItem
from MyThread import MyThread
from ipconfig import get_interfaces_name
from scapy.all import *
from Packet import Packet_Item

class SnifferWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.display_interfaces_list()
        self.show()

        #初始化抓包窗口
        self.captured_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.captured_view.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        # self.captured_view.resizeColumnToContents()

        # 初始化抓包线程
        self.thread = MyThread()
        self.thread.task_finished.connect(self.update_packets_list)
        self.sniff_button.clicked.connect(self.start_sniff_thread)

    def set_captured_view_header(self):
        self.captured_view.setVerticalHeader()

    def display_interfaces_list(self):
        interifaces_list = get_interfaces_name()
        self.interfaces_combo.addItems(interifaces_list)

    def start_sniff_thread(self):
        # 设置按钮
        self.sniff_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.resniff_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        # 开始抓包前清除所有数据
        self.captured_view.clearContents()
        self.thread.start()

    def update_packets_list(self, packet_item = Packet_Item):
        current_row_count = self.captured_view.rowCount()
        self.captured_view.setRowCount(current_row_count + 1)
        self.captured_view.setItem(current_row_count, 0, packet_item)
        # self.captured_view.setItem(current_row_count, 1, packet)
        # self.captured_view.setItem(current_row_count, 2, packet.)
        # self.captured_view.setItem(current_row_count, 3, current_row_count + 1)
        # self.captured_view.setItem(current_row_count, 4, current_row_count + 1)
        # self.captured_view.setItem(current_row_count, 5, current_row_count + 1)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = SnifferWindow()
    sys.exit(app.exec())
