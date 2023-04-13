import sys
from MainWindow import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow, QApplication, QTableWidgetItem, QTableWidget, QAbstractItemView
from logic import add_combo_items
from ipconfig import get_interfaces_name
import capture_packets
from MyThread import MyThread

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

        self.sniff_button.clicked.connect(self.start_sniff)


    def set_captured_view_header(self):
        self.captured_view.setVerticalHeader()
    def display_interfaces_list(self):
        interifaces_list = get_interfaces_name()
        self.interfaces_combo.addItems(interifaces_list)

    def start_sniff(self):
        self.sniff_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.resniff_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        # self.thread = MyThread(self.captured_view, self.captured_view, interface_name = self.interfaces_combo.currentData())
        self.thread = MyThread()
        self.thread.task_finished.connect(self.update_table_widget)
        self.thread.start()

    def display_captured_packets(self):
        return

    def update_table_widget(self, number, time, source, destination, protocal, length, info):
        row = self.captured_view.rowCount()
        self.captured_view.insertRow(row)
        number_item = QTableWidgetItem(number)
        time_item = QTableWidgetItem(time)
        source_item = QTableWidgetItem(source)
        destination_item = QTableWidgetItem(destination)
        protocal_item = QTableWidgetItem(protocal)
        length_item = QTableWidgetItem(length)
        info_item = QTableWidgetItem(info)
        self.captured_view.setItem(row, 0, number_item)
        self.captured_view.setItem(row, 1, time_item)
        self.captured_view.setItem(row, 2, source_item)
        self.captured_view.setItem(row, 3, destination_item)
        self.captured_view.setItem(row, 4, protocal_item)
        self.captured_view.setItem(row, 5, length_item)
        self.captured_view.setItem(row, 6, info_item)
        self.captured_view.resizeColumnsToContents()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = SnifferWindow()
    sys.exit(app.exec())
