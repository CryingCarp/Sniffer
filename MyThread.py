import sys
from PyQt6.QtWidgets import QApplication, QWidget
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QPushButton, QLabel, QVBoxLayout


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        # 设置窗口的标题和大小
        self.setWindowTitle('网络抓包器')
        self.setGeometry(300, 300, 400, 300)

        # 创建标签和按钮
        self.label = QLabel(self)
        self.label.setText('正在捕获包...')
        self.label.setWindowIcon(QIcon('icon.png'))
        self.label.move(50, 50)

        self.button = QPushButton(self)
        self.button.setText('开始抓包')
        self.button.move(150, 50)

        # 创建布局
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.label)
        self.layout.addWidget(self.button)
        self.setLayout(self.layout)

        # 创建信号与槽函数的连接
        self.button.clicked.connect(self.start_capture)

    def start_capture(self):
        # 创建线程用于捕获包
        thread = QThread(self)
        thread.start()

        # 显示线程的进度
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(200, 100, 100, 20)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.update_progress_bar()

    def update_progress_bar(self):
        current_value = self.progress_bar.value()
        total_value = 100

        # 更新进度条的值
        self.label.setText(f'捕获包进度:{current_value}/{total_value}')

        # 更新线程的状态
        self.thread_status.setText(f'正在捕获包，进度:{current_value}/{total_value}')

        # 更新线程的进度
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(current_value)

        # 等待线程完成
        self.thread.join()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
