from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit
import os

class ProcessAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Monitor Running Processes Button
        self.monitor_button = QPushButton("Monitor Running Processes")
        self.monitor_button.clicked.connect(self.monitor_processes)
        self.layout().addWidget(self.monitor_button)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

    def monitor_processes(self):
        self.results_display.append("Monitoring running processes...\n")
        command = "ps aux"
        result = os.popen(command).read()
        self.results_display.append(f"Running Processes:\n{result}\n")
