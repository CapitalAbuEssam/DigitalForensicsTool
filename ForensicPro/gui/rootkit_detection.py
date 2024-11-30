import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit

class RootkitDetectionTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Title
        self.title = QLabel("Rootkit Detection")
        self.layout().addWidget(self.title)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # Buttons
        self.chkrootkit_button = QPushButton("Run chkrootkit")
        self.chkrootkit_button.clicked.connect(self.run_chkrootkit)
        self.layout().addWidget(self.chkrootkit_button)

        self.rkhunter_button = QPushButton("Run rkhunter")
        self.rkhunter_button.clicked.connect(self.run_rkhunter)
        self.layout().addWidget(self.rkhunter_button)

    def run_chkrootkit(self):
        self.results_display.append("Running chkrootkit...\n")
        try:
            result = subprocess.getoutput("sudo chkrootkit")
            self.results_display.append(result + "\n")
        except Exception as e:
            self.results_display.append(f"Error running chkrootkit: {e}\n")

    def run_rkhunter(self):
        self.results_display.append("Running rkhunter...\n")
        try:
            result = subprocess.getoutput("sudo rkhunter --check")
            self.results_display.append(result + "\n")
        except Exception as e:
            self.results_display.append(f"Error running rkhunter: {e}\n")
