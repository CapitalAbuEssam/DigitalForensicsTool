import os
import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog

class MemoryForensicsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Title
        self.title = QLabel("Memory Forensics (Volatility 3)")
        self.layout().addWidget(self.title)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # Buttons
        self.load_memory_button = QPushButton("Load Memory Dump")
        self.load_memory_button.clicked.connect(self.load_memory_dump)
        self.layout().addWidget(self.load_memory_button)

        self.analyze_button = QPushButton("Analyze Memory")
        self.analyze_button.clicked.connect(self.analyze_memory)
        self.analyze_button.setEnabled(False)
        self.layout().addWidget(self.analyze_button)

    def load_memory_dump(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump", "", "Raw Files (*.raw);;All Files (*)", options=options)
        if file_path:
            self.memory_dump_path = file_path
            self.results_display.append(f"Loaded memory dump: {file_path}\n")
            self.analyze_button.setEnabled(True)

    def analyze_memory(self):
        try:
            self.results_display.append("Starting memory analysis...\n")
            
            # Correct the path to the vol.py script
            volatility_path = "/home/kali/Desktop/ForensicPro/volatility3-2.8.0/vol.py"
            
            # Ensure you're referencing the correct vol.py in the Volatility 3 directory
            commands = [
                f"python3 {volatility_path} -f {self.memory_dump_path} windows.pslist.PsList",
                f"python3 {volatility_path} -f {self.memory_dump_path} windows.netscan.NetScan",
                f"python3 {volatility_path} -f {self.memory_dump_path} windows.malfind.Malfind"
            ]

            for command in commands:
                self.results_display.append(f"Running: {command}\n")
                result = subprocess.getoutput(command)
                self.results_display.append(result + "\n")
        except Exception as e:
            self.results_display.append(f"Error during memory analysis: {e}\n")
