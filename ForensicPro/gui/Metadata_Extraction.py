from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog
import os

class MetadataAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Select File Button
        self.file_button = QPushButton("Select File for Metadata Analysis")
        self.file_button.clicked.connect(self.select_file)
        self.layout().addWidget(self.file_button)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # File Path for Analysis
        self.file_to_analyze = None

    def select_file(self):
        self.file_to_analyze, _ = QFileDialog.getOpenFileName(self, "Select File")
        if self.file_to_analyze:
            self.results_display.append(f"Selected File: {self.file_to_analyze}\n")
            self.analyze_metadata()

    def analyze_metadata(self):
        if not self.file_to_analyze:
            self.results_display.append("No file selected for analysis.\n")
            return

        self.results_display.append(f"Analyzing metadata for {self.file_to_analyze}...\n")
        command = f"exiftool {self.file_to_analyze}"
        result = os.popen(command).read()
        self.results_display.append(f"Metadata Analysis Results:\n{result}\n")
