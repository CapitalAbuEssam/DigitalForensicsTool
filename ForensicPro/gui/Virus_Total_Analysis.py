import requests
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QFileDialog

class VirusTotalTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Label and API Key Input
        self.api_key_label = QLabel("Enter VirusTotal API Key:")
        self.layout().addWidget(self.api_key_label)

        self.api_key_input = QLineEdit()
        self.layout().addWidget(self.api_key_input)

        # File Hash Analysis
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter file hash to check")
        self.layout().addWidget(self.hash_input)

        self.hash_button = QPushButton("Analyze Hash")
        self.hash_button.clicked.connect(self.analyze_hash)
        self.layout().addWidget(self.hash_button)

        # File Upload Analysis
        self.file_button = QPushButton("Upload File to Analyze")
        self.file_button.clicked.connect(self.upload_file)
        self.layout().addWidget(self.file_button)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

    def analyze_hash(self):
        api_key = self.api_key_input.text().strip()
        file_hash = self.hash_input.text().strip()
        if not api_key or not file_hash:
            self.results_display.append("API key and file hash are required.\n")
            return

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)
            result = response.json()
            self.results_display.append(f"Hash Analysis Result:\n{result}\n")
        except Exception as e:
            self.results_display.append(f"Error: {e}\n")

    def upload_file(self):
        api_key = self.api_key_input.text().strip()
        if not api_key:
            self.results_display.append("API key is required.\n")
            return

        file_path = QFileDialog.getOpenFileName(self, "Select File to Upload")[0]
        if not file_path:
            return

        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": api_key}
        files = {"file": open(file_path, "rb")}

        try:
            response = requests.post(url, headers=headers, files=files)
            result = response.json()
            self.results_display.append(f"File Upload Result:\n{result}\n")
        except Exception as e:
            self.results_display.append(f"Error: {e}\n")
