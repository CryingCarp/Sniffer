import sys
from MainWindow import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow, QApplication
# from logic import add_combo_items
from ipconfig import get_interfaces_name
import capture_packets

class SnifferWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.display_interfaces_list()
        self.show()

        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.resniff_button.setEnabled(False)

        self.sniff_button.clicked.connect(self.start_sniff)

    def display_interfaces_list(self):
        interifaces_list = get_interfaces_name()
        self.interfaces_combo.addItems(interifaces_list)


    def start_sniff(self):
        self.sniff_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.resniff_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        selected_interface = self.interfaces_combo.currentData()
        packets_list = capture_packets.sniff_all_packets(selected_interface)


    def display_captured_packets(self):
        return

if __name__ == "__main__":
    app = QApplication(sys.argv)
    sniffer = SnifferWindow()
    sys.exit(app.exec())
