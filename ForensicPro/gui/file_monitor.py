from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, update_callback):
        super().__init__()
        self.update_callback = update_callback

    def on_created(self, event):
        self.update_callback("Created", event.src_path)

    def on_modified(self, event):
        self.update_callback("Modified", event.src_path)

    def on_deleted(self, event):
        self.update_callback("Deleted", event.src_path)

class FileMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Label and Select Folder Button
        self.label = QLabel("No folder selected")
        self.layout().addWidget(self.label)

        self.select_folder_button = QPushButton("Select Folder to Monitor")
        self.select_folder_button.clicked.connect(self.select_folder)
        self.layout().addWidget(self.select_folder_button)

        # Event Table
        self.event_table = QTableWidget()
        self.event_table.setColumnCount(2)
        self.event_table.setHorizontalHeaderLabels(["Event Type", "File Path"])
        self.layout().addWidget(self.event_table)

        # Observer setup
        self.observer = None

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.label.setText(f"Monitoring folder: {folder}")
            self.start_monitoring(folder)

    def start_monitoring(self, folder):
        if self.observer:
            self.observer.stop()

        # Create a new observer
        self.observer = Observer()
        handler = FileMonitorHandler(self.update_table)
        self.observer.schedule(handler, folder, recursive=True)

        # Run the observer in a thread
        threading.Thread(target=self.observer.start, daemon=True).start()

    def update_table(self, event_type, file_path):
        row = self.event_table.rowCount()
        self.event_table.insertRow(row)
        self.event_table.setItem(row, 0, QTableWidgetItem(event_type))
        self.event_table.setItem(row, 1, QTableWidgetItem(file_path))

    def closeEvent(self, event):
        if self.observer:
            self.observer.stop()
