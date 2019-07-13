# SWAMI KARUPPASWAMI THUNNAI

import sys
import time
import json
import hashlib
import requests
import pickle
import psutil
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot


class VTScanProcess:

    def __init__(self, api_key, scan_id=None, signal=None):
        self.api_key = api_key
        self.process_list = []
        self.signal = signal
        self.scan_id = scan_id
        self.scanned_list = []
        if self.scan_id:
            self.report = []

    def get_process_list(self):
        for process in psutil.process_iter():
            process_dict = process.as_dict(attrs=["pid", "name", "exe"])
            if process_dict["exe"]:
                self.process_list.append(process_dict)

    def scan(self):
        self.get_process_list()
        with open("whitelist.pkl", "rb") as pkl:
            pure_hashes = pickle.load(pkl)
        for i, process in enumerate(self.process_list):
            process_path = process["exe"]
            r = requests.post("http://127.0.0.1:5660/get_tlsh", data={"file": process_path})
            tlsh_hash = r.json()["message"]
            if len(tlsh_hash) > 0:
                for _hash in pure_hashes:
                    r = requests.get("http://127.0.0.1:5660/get_tlsh_distance?"
                                     "hash_one={}&hash_two={}".format(tlsh_hash, _hash))
                    result = r.json()["message"]
                    if result != -1:
                        if result < 20:
                            del self.process_list[i]
                            print("PROCSCAN ", process_path, " IS IN WHITELIST")

        for process in self.process_list:
            process_path = process["exe"]
            if process_path not in self.scanned_list:
                try:
                    md5_hash = self.calculate_md5(process_path)
                    url = 'https://www.virustotal.com/vtapi/v2/file/report'
                    params = {'apikey': self.api_key, 'resource': md5_hash}
                    response = requests.get(url, params=params)
                    positives = response.json()["positives"]
                    total = response.json()["total"]
                    if self.scan_id:
                        print("SCANNED PID: ", process["pid"])
                        self.report.append([process["pid"], process["name"], process["exe"], positives, total])
                    else:
                        self.signal.emit({"name": process["name"], "exe": process["exe"], "positives": positives,
                                          "total": total})
                    self.scanned_list.append(process_path)
                    time.sleep(25)
                except Exception as e:
                    print(e)

        if self.scan_id:
            with open("report" + self.scan_id + ".json", "w") as file:
                file.write(json.dumps({"report": self.report}, indent=4))

    def calculate_md5(self, process_path):
        hash_md5 = hashlib.md5()
        with open(process_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()


class VTScanProcessThread(QThread):

    def __init__(self, api_key, signal, completed_signal):
        QThread.__init__(self)
        self.api_key = api_key
        self.signal = signal
        self.completed_signal = completed_signal

    def run(self):
        VTScanProcess(api_key=self.api_key, signal=self.signal).scan()
        self.completed_signal.emit("Completed!")


class VTScanProcessGUI(QWidget):

    signal = pyqtSignal(dict)
    completed_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.signal.connect(self.add_process)
        self.completed_signal.connect(self.completed_slot)
        self.setWindowTitle("VirusTotal Process Scanner [SCANNING]")
        self.setGeometry(300, 300, 800, 600)
        main_layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(("Process Name", "Process Location", "Detection", "Total"))
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 350)
        main_layout.addWidget(self.table)
        self.thread = VTScanProcessThread(api_key, self.signal, self.completed_signal)
        self.thread.start()
        self.setLayout(main_layout)

    @pyqtSlot(dict)
    def add_process(self, value):
        row_count = self.table.rowCount()
        self.table.setRowCount(row_count+1)
        self.table.setItem(row_count, 0, QTableWidgetItem(str(value["name"])))
        self.table.setItem(row_count, 1, QTableWidgetItem(str(value["exe"])))
        self.table.setItem(row_count, 2, QTableWidgetItem(str(value["positives"])))
        self.table.setItem(row_count, 3, QTableWidgetItem(str(value["total"])))

    @pyqtSlot(str)
    def completed_slot(self, value):
        self.setWindowTitle("VirusTotal Process Scanner [COMPLETED]")


if __name__ == "__main__":
    contents = sys.argv
    if len(contents) < 3:
        sys.exit(-1)
    api_key = contents[2]
    if contents[1] == "gui":
        app = QApplication(sys.argv)
        gui = VTScanProcessGUI()
        gui.show()
        sys.exit(app.exec())
    elif contents[1] == "cmd":
        report_id = contents[3]
        print("GENERATING REPORT - THIS WILL TAKE SOME TIME")
        VTScanProcess(api_key, report_id).scan()

