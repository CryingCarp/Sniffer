import sys
from MainWindow import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow, QApplication
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


    def display_captured_packets(self):
        return

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = SnifferWindow()
    sys.exit(app.exec())
