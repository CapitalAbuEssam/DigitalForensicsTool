from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit
import os

class USBAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Analyze USB Devices Button
        self.usb_button = QPushButton("Analyze USB Devices")
        self.usb_button.clicked.connect(self.analyze_usb)
        self.layout().addWidget(self.usb_button)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

    def analyze_usb(self):
        self.results_display.append("Analyzing connected USB devices...\n")
        command = "lsusb"
        result = os.popen(command).read()
        self.results_display.append(f"Connected USB Devices:\n{result}\n")
