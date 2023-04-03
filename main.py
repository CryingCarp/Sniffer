import sys
from MainWindow import Ui_MainWindow
from PyQt6 import QtWidgets
from logic import add_combo_items
from ipconfig import get_interfaces_name

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    interfaces_list = get_interfaces_name()
    add_combo_items(interfaces_list, ui)
    MainWindow.show()
    sys.exit(app.exec())

# app = QtWidgets.QApplication(sys.argv)
# MainWindow = QtWidgets.QMainWindow()
# ui = Ui_MainWindow()
# ui.setupUi(MainWindow)
# MainWindow.show()
# sys.exit(app.exec())

