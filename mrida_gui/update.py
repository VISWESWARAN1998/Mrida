# SWAMI KARUPPASWAMI THUNNAI

import sqlite3
import requests
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QListWidget, QPushButton
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot


class UpdateThread(QThread):

    def __init__(self, signal):
        QThread.__init__(self)
        self.signal = signal

    def run(self):
        self.signal.emit("UPDATE INITIATED")
        connection = sqlite3.connect("ruleset.db")
        cursor = connection.cursor()
        cursor.execute("create table if not exists completed(id bigint)")
        cursor.execute("create table if not exists pending(url text)")
        cursor.close()
        connection.close()
        self.download_rule_sets()
        self.download_pending()
        self.signal.emit("UPDATED!")

    def download_rule_sets(self):
        connection = sqlite3.connect("ruleset.db")
        cursor = connection.cursor()
        cursor.execute("select max(id) as max from completed")
        result = cursor.fetchone()
        result = result[0]
        if result:
            result += 1
        else:
            result = 1
        while True:
            try:
                r = requests.get("https://raw.githubusercontent.com/VISWESWARAN1998/"
                                 "open-threat-database/master/ruleset/rule_set"+str(result)+".json")
                content = r.json()
                url = content["url"]
                files = content["files"]
                for file in files:
                    self.signal.emit("FOUND: "+file)
                    cursor.execute("insert into pending(url) values(?)", (url+file, ))
                    connection.commit()
                cursor.execute("insert into completed(id) values(?)", (result, ))
                connection.commit()
                self.signal.emit("Downloaded Ruleset: "+str(result)+".json")
                result += 1
            except Exception as e:
                break
        cursor.close()
        connection.close()

    def download_pending(self):
        connection = sqlite3.connect("ruleset.db")
        cursor = connection.cursor()
        cursor.execute("select url from pending")
        result = cursor.fetchall()
        if len(result) > 0:
            for url in result:
                url = url[0]
                self.signal.emit("FETCHING: "+url)
                try:
                    r = requests.get(url)
                    value = r.json()
                    tlsh = value["tlsh"]
                    name = value["name"]
                    size = value["size"]
                    file_type = value["type"]
                    r = requests.post("http://127.0.0.1:5660/add_threat", data={"hash": tlsh, "name": name, "size":size,
                                                                                "type":file_type})
                    if r.json()["message"] is True:
                        cursor.execute("delete from pending where url=?", (url, ))
                        connection.commit()
                        self.signal.emit("UPDATED SIGNATURE: "+name+"~"+str(size))
                except Exception as e:
                    self.signal.emit(str(e))
        cursor.close()
        connection.close()


class UpdateWidget(QWidget):

    signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.update_thread = None
        self.signal.connect(self.update_slot)
        main_layout = QVBoxLayout()
        self.update_list = QListWidget()
        main_layout.addWidget(self.update_list)
        update = QPushButton("UPDATE")
        update.clicked.connect(self.update_clicked)
        main_layout.addWidget(update)
        self.setLayout(main_layout)
    
    @pyqtSlot(str)
    def update_slot(self, value):
        self.update_list.addItem(value)
        self.update_list.scrollToBottom()

    def update_clicked(self):
        self.update_thread = UpdateThread(self.signal)
        self.update_thread.start()

