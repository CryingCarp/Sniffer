# Form implementation generated from reading ui file '/Users/ariete/PycharmProjects/pythonProject/MainWindow.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1062, 800)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(1000, 800))
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.packet_browser = QtWidgets.QTextBrowser(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.packet_browser.sizePolicy().hasHeightForWidth())
        self.packet_browser.setSizePolicy(sizePolicy)
        self.packet_browser.setMinimumSize(QtCore.QSize(500, 300))
        self.packet_browser.setObjectName("packet_browser")
        self.gridLayout.addWidget(self.packet_browser, 4, 0, 1, 1)
        self.captured_view = QtWidgets.QTableWidget(parent=self.centralwidget)
        self.captured_view.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.captured_view.sizePolicy().hasHeightForWidth())
        self.captured_view.setSizePolicy(sizePolicy)
        self.captured_view.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.captured_view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.captured_view.setAlternatingRowColors(True)
        self.captured_view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.captured_view.setShowGrid(False)
        self.captured_view.setRowCount(0)
        self.captured_view.setObjectName("captured_view")
        self.captured_view.setColumnCount(7)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.captured_view.setHorizontalHeaderItem(6, item)
        self.captured_view.horizontalHeader().setVisible(True)
        self.captured_view.horizontalHeader().setMinimumSectionSize(25)
        self.captured_view.horizontalHeader().setStretchLastSection(True)
        self.captured_view.verticalHeader().setVisible(False)
        self.captured_view.verticalHeader().setDefaultSectionSize(25)
        self.captured_view.verticalHeader().setMinimumSectionSize(20)
        self.gridLayout.addWidget(self.captured_view, 1, 0, 1, 3)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.sniff_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.sniff_button.setObjectName("sniff_button")
        self.horizontalLayout.addWidget(self.sniff_button)
        self.pause_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pause_button.setEnabled(False)
        self.pause_button.setObjectName("pause_button")
        self.horizontalLayout.addWidget(self.pause_button)
        self.stop_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.stop_button.setEnabled(False)
        self.stop_button.setObjectName("stop_button")
        self.horizontalLayout.addWidget(self.stop_button)
        self.resniff_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.resniff_button.setEnabled(False)
        self.resniff_button.setObjectName("resniff_button")
        self.horizontalLayout.addWidget(self.resniff_button)
        self.interfaces_combo = QtWidgets.QComboBox(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.interfaces_combo.sizePolicy().hasHeightForWidth())
        self.interfaces_combo.setSizePolicy(sizePolicy)
        self.interfaces_combo.setMinimumSize(QtCore.QSize(150, 0))
        self.interfaces_combo.setObjectName("interfaces_combo")
        self.horizontalLayout.addWidget(self.interfaces_combo)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 3)
        self.hex_browser = QtWidgets.QTextBrowser(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.hex_browser.sizePolicy().hasHeightForWidth())
        self.hex_browser.setSizePolicy(sizePolicy)
        self.hex_browser.setMinimumSize(QtCore.QSize(500, 300))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setKerning(False)
        self.hex_browser.setFont(font)
        self.hex_browser.setObjectName("hex_browser")
        self.gridLayout.addWidget(self.hex_browser, 4, 1, 1, 2)
        self.horizontalLayout_2.addLayout(self.gridLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1062, 21))
        self.menubar.setObjectName("menubar")
        self.menu = QtWidgets.QMenu(parent=self.menubar)
        self.menu.setObjectName("menu")
        self.menu_2 = QtWidgets.QMenu(parent=self.menubar)
        self.menu_2.setObjectName("menu_2")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionopen = QtGui.QAction(parent=MainWindow)
        self.actionopen.setObjectName("actionopen")
        self.actionclose = QtGui.QAction(parent=MainWindow)
        self.actionclose.setObjectName("actionclose")
        self.actionsave_as = QtGui.QAction(parent=MainWindow)
        self.actionsave_as.setObjectName("actionsave_as")
        self.menu.addAction(self.actionopen)
        self.menu.addAction(self.actionclose)
        self.menu.addAction(self.actionsave_as)
        self.menubar.addAction(self.menu.menuAction())
        self.menubar.addAction(self.menu_2.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "嗅探器"))
        self.captured_view.setSortingEnabled(True)
        item = self.captured_view.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "序号"))
        item = self.captured_view.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "时间"))
        item = self.captured_view.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "源地址"))
        item = self.captured_view.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "目的地址"))
        item = self.captured_view.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "协议"))
        item = self.captured_view.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "长度"))
        item = self.captured_view.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "info"))
        self.sniff_button.setText(_translate("MainWindow", "开始抓包"))
        self.pause_button.setText(_translate("MainWindow", "暂停"))
        self.stop_button.setText(_translate("MainWindow", "停止"))
        self.resniff_button.setText(_translate("MainWindow", "重新抓包"))
        self.menu.setTitle(_translate("MainWindow", "菜单"))
        self.menu_2.setTitle(_translate("MainWindow", "文件"))
        self.actionopen.setText(_translate("MainWindow", "open"))
        self.actionclose.setText(_translate("MainWindow", "close"))
        self.actionsave_as.setText(_translate("MainWindow", "save as"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
