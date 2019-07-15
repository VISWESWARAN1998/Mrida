# SWAMI KARUPPASWAMI THUNNAI

import os
import requests
import filetype
from PyQt5.QtWidgets import QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QListWidget
from PyQt5.QtWidgets import QFileDialog, QCheckBox, QListWidgetItem, QMessageBox
from PyQt5.QtCore import QThread, QDir, QDirIterator, pyqtSignal, pyqtSlot


class DetectionWidget(QWidget):

    def __init__(self, path, author, name, description):
        super().__init__()
        main_layout = QVBoxLayout()
        self.select_threat = QCheckBox(name)
        main_layout.addWidget(self.select_threat)
        self.path = QLabel()
        self.path.setStyleSheet("color: red")
        main_layout.addWidget(self.path)
        self.author = QLabel()
        self.description = QLabel()
        self.description.setText("Description: " + description)
        self.author.setText("Author: "+author)
        self.path.setText(path)
        main_layout.addWidget(self.author)
        main_layout.addWidget(self.description)
        self.setLayout(main_layout)

    def is_checked(self):
        return self.select_threat.isChecked()

    def get_path(self):
        return self.path.text()


class ScanThread(QThread):

    def __init__(self, folder_location, scanning_signal, detection_signal):
        QThread.__init__(self)
        self.folder_location = folder_location
        self.scanning_signal = scanning_signal
        self.detection_signal = detection_signal

    def run(self):
        if not os.path.exists(self.folder_location):
            return None
        filter = QDir.Dirs | QDir.Files | QDir.Hidden
        iterator = QDirIterator(self.folder_location, filter, QDirIterator.Subdirectories)
        while iterator.hasNext():
            path = iterator.next()
            if os.path.isfile(path):
                file_name = os.path.split(path)
                self.scanning_signal.emit("[SCANNING]: "+file_name[1])
                self.scan_for_yara(path=path)
                self.scan_for_tlsh(path=path)
        self.scanning_signal.emit(None)

    def scan_for_yara(self, path):
        r = requests.post("http://127.0.0.1:5660/scan_file_for_yara", data={"file": path, "target": "all"})
        content = r.json()
        if content["message"] is True:
            for detection in content["detections"]:
                detection["path"] = path
                self.detection_signal.emit(detection)

    def scan_for_tlsh(self, path):
        r = requests.post("http://127.0.0.1:5660/get_tlsh", data={"file": path})
        tlsh_hash = r.json()["message"]
        if len(tlsh_hash) != 70:
            return None
        try:
            file_size = os.path.getsize(path)
            file_type = filetype.guess(path)
            mime = file_type.mime
            r = requests.get("http://127.0.0.1:5660/check_threat_db?tlsh={}7&min_size={}&max_size={}&type={}".format(
                tlsh_hash, file_size-10000, file_size+10000, mime
            ))
            if r.json()["message"] != -1:
                result = {
                    "name": "Identified Threat",
                    "author": "Undefined",
                    "description": "This application matches known sample collected from virussign.",
                    "path": path
                }
                self.detection_signal.emit(result)
        except AttributeError:
            pass


class ScanWidget(QWidget):

    scanning_signal = pyqtSignal(str)
    detection_siganl = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.scanning_signal.connect(self.scanning_slot)
        self.detection_siganl.connect(self.detection_slot)
        main_layout = QVBoxLayout()
        selection_layout = QHBoxLayout()
        self.folder_location = QLineEdit()
        selection_layout.addWidget(self.folder_location)
        choose_folder = QPushButton("CHOOSE DIR")
        choose_folder.clicked.connect(self.choose_folder_clicked)
        start_scan = QPushButton("SCAN")
        start_scan.clicked.connect(self.scan_clicked)
        stop_scan = QPushButton("STOP")
        stop_scan.clicked.connect(self.stop_clicked)
        selection_layout.addWidget(choose_folder)
        selection_layout.addWidget(start_scan)
        selection_layout.addWidget(stop_scan)
        main_layout.addLayout(selection_layout)
        self.status = QLabel()
        main_layout.addWidget(self.status)
        self.scan_result = QListWidget()
        main_layout.addWidget(self.scan_result)
        detection_layout = QHBoxLayout()
        delete_selected = QPushButton("DELETE SELECTED")
        delete_selected.clicked.connect(self.delete_selected_clicked)
        delete_all = QPushButton("DELETE ALL")
        delete_all.clicked.connect(self.delete_all_clicked)
        detection_layout.addWidget(delete_selected)
        detection_layout.addWidget(delete_all)
        main_layout.addLayout(detection_layout)
        self.setLayout(main_layout)

    def choose_folder_clicked(self):
        folder_location = QFileDialog.getExistingDirectory(self, "Choose Directory")
        self.folder_location.setText(folder_location)

    def scan_clicked(self):
        self.scan_thread = ScanThread(self.folder_location.text(), self.scanning_signal, self.detection_siganl)
        self.scan_thread.start()

    @pyqtSlot(str)
    def scanning_slot(self, value):
        if value:
            self.status.setText(value)
        else:
            QMessageBox.information(self, "Mrida", "Scan has been completed!")

    @pyqtSlot(dict)
    def detection_slot(self, value):
        self.scan_result.scrollToBottom()
        item = QListWidgetItem(self.scan_result)
        widget = DetectionWidget(path=value["path"], author=value["author"], name=value["name"],
                                 description=value["description"])
        item.setSizeHint(widget.sizeHint())
        self.scan_result.setItemWidget(item, widget)

    def stop_clicked(self):
        self.scan_thread.terminate()

    def delete_selected_clicked(self):
        paths = []
        for i in range(self.scan_result.count()):
            widget = self.scan_result.itemWidget(self.scan_result.item(i))
            if widget.is_checked():
                if os.path.exists(widget.get_path()):
                    paths.append((widget.get_path(), i))
        for path in paths:
            if os.path.exists(path[0]):
                os.remove(path[0])
                self.scan_result.takeItem(path[1])

    def delete_all_clicked(self):
        paths = []
        for i in range(self.scan_result.count()):
            widget = self.scan_result.itemWidget(self.scan_result.item(i))
            if os.path.exists(widget.get_path()):
                paths.append((widget.get_path(), i))
        for path in paths:
            if os.path.exists(path[0]):
                os.remove(path[0])
                self.scan_result.takeItem(path[1])