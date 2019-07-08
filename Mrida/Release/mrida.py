# SWAMI KARUPPASWAMI THUNNAI

import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QTabWidget
from PyQt5.QtCore import Qt
from scan import ScanWidget


class MridaMainWidget(QTabWidget):

    def __init__(self):
        super().__init__()
        self.addTab(ScanWidget(), "Scan")


class MridaMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mrida Anti-Malware")
        self.setGeometry(300, 300, 900, 600)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
        self.setCentralWidget(MridaMainWidget())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mrida = MridaMainWindow()
    mrida.show()
    sys.exit(app.exec())