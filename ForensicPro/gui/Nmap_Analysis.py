import os
import subprocess
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel,
    QProgressBar, QMessageBox, QFileDialog, QInputDialog  # Added QInputDialog import
)
from PyQt5.QtCore import QThread, pyqtSignal
import xml.etree.ElementTree as ET
import plotly.express as px

class NmapWorker(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, command, output_file):
        super().__init__()
        self.command = command
        self.output_file = output_file

    def run(self):
        """
        Executes the Nmap command in a separate thread.
        """
        try:
            self.progress_signal.emit(10)  # Update progress
            subprocess.run(self.command, shell=True, check=True)  # Run Nmap
            self.progress_signal.emit(50)
            if os.path.exists(self.output_file):
                self.progress_signal.emit(100)
                self.result_signal.emit(self.output_file)
            else:
                self.error_signal.emit("Output file not generated.")
        except subprocess.CalledProcessError as e:
            self.error_signal.emit(f"Nmap execution failed: {str(e)}")
        except Exception as e:
            self.error_signal.emit(f"Unexpected error: {str(e)}")


class LegendaryNmapTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())
        self.output_file = "nmap_output.xml"
        self.scan_results = {}  # For parsed results
        self.executor = None
        self.nmap_worker = None
        self.setup_ui()

    def setup_ui(self):
        """
        Set up the GUI layout for the Nmap Tab.
        """
        self.target_label = QLabel("Target Host/IP:")
        self.layout().addWidget(self.target_label)

        self.target_input = QLineEdit()
        self.layout().addWidget(self.target_input)

        # Buttons for Nmap options
        self.regular_scan_button = QPushButton("Regular Scan")
        self.regular_scan_button.clicked.connect(lambda: self.run_nmap_in_background("-sS"))
        self.layout().addWidget(self.regular_scan_button)

        self.aggressive_scan_button = QPushButton("Aggressive Scan")
        self.aggressive_scan_button.clicked.connect(lambda: self.run_nmap_in_background("-A"))
        self.layout().addWidget(self.aggressive_scan_button)

        self.os_detection_button = QPushButton("OS Detection")
        self.os_detection_button.clicked.connect(lambda: self.run_nmap_in_background("-O"))
        self.layout().addWidget(self.os_detection_button)

        self.custom_scan_button = QPushButton("Custom Scan")
        self.custom_scan_button.clicked.connect(self.custom_scan)
        self.layout().addWidget(self.custom_scan_button)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.layout().addWidget(self.progress_bar)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # Charts button
        self.charts_button = QPushButton("Generate Charts")
        self.charts_button.clicked.connect(self.generate_charts)
        self.charts_button.setEnabled(False)
        self.layout().addWidget(self.charts_button)

    def run_nmap_in_background(self, options):
        """
        Run Nmap in a separate thread.
        """
        self.target = self.target_input.text().strip()
        if not self.target:
            QMessageBox.warning(self, "Input Error", "Please enter a valid target.")
            return

        self.results_display.append(f"Starting Nmap scan with options: {options}\n")
        command = f"nmap {options} -oX {self.output_file} {self.target}"
        self.progress_bar.setValue(0)

        # Initialize and start worker thread
        self.nmap_worker = NmapWorker(command, self.output_file)
        self.nmap_worker.progress_signal.connect(self.update_progress)
        self.nmap_worker.result_signal.connect(self.handle_scan_success)
        self.nmap_worker.error_signal.connect(self.handle_scan_error)
        self.nmap_worker.start()

    def update_progress(self, value):
        """
        Updates the progress bar.
        """
        self.progress_bar.setValue(value)

    def handle_scan_success(self, file_path):
        """
        Handles successful completion of the scan.
        """
        self.results_display.append("Scan completed! Parsing results...\n")
        self.parse_results(file_path)

    def handle_scan_error(self, error_message):
        """
        Handles errors during the scan.
        """
        self.results_display.append(f"Error: {error_message}\n")
        self.progress_bar.setValue(0)

    def parse_results(self, file_path):
        """
        Parses the XML output from Nmap.
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            hosts = []

            for host in root.findall("host"):
                addr = host.find("address").attrib["addr"]
                status = host.find("status").attrib["state"]
                ports = []

                for port in host.findall("ports/port"):
                    port_id = port.attrib["portid"]
                    protocol = port.attrib["protocol"]
                    state = port.find("state").attrib["state"]
                    ports.append((port_id, protocol, state))

                hosts.append({"address": addr, "status": status, "ports": ports})

            self.scan_results = {"hosts": hosts}
            self.display_results()
            self.charts_button.setEnabled(True)  # Enable charts generation
        except ET.ParseError:
            QMessageBox.warning(self, "Parsing Error", "The Nmap output file could not be parsed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error while parsing: {e}")

    def display_results(self):
        """
        Displays parsed results in the GUI.
        """
        self.results_display.clear()
        for host in self.scan_results["hosts"]:
            self.results_display.append(f"Host: {host['address']} (Status: {host['status']})\n")
            for port in host["ports"]:
                self.results_display.append(f"  Port: {port[0]} | Protocol: {port[1]} | State: {port[2]}\n")
            self.results_display.append("\n")

    def generate_charts(self):
        """
        Generates a pie chart of protocols and bar chart of port states.
        """
        protocol_counts = {}
        state_counts = {}

        for host in self.scan_results["hosts"]:
            for port in host["ports"]:
                protocol_counts[port[1]] = protocol_counts.get(port[1], 0) + 1
                state_counts[port[2]] = state_counts.get(port[2], 0) + 1

        # Protocol Pie Chart
        fig1 = px.pie(
            names=list(protocol_counts.keys()), 
            values=list(protocol_counts.values()), 
            title="Protocol Distribution"
        )
        fig1.show()

        # Port States Bar Chart
        fig2 = px.bar(
            x=list(state_counts.keys()), 
            y=list(state_counts.values()), 
            labels={"x": "Port States", "y": "Count"},
            title="Port States Distribution"
        )
        fig2.show()

    def custom_scan(self):
        """
        Opens a dialog for custom Nmap options.
        """
        nmap_options, ok = QInputDialog.getText(
            self,
            "Custom Nmap Scan",
            "Enter Nmap options (e.g., -sS -p 80,443 192.168.1.1):"
        )

        if ok and nmap_options.strip():  # If user clicks OK and enters something
            self.results_display.append(f"Running custom Nmap scan with options: {nmap_options}\n")

            # Run Nmap with the provided options
            command = f"nmap {nmap_options}"
            try:
                result = os.popen(command).read()
                self.results_display.append(f"Custom Nmap Scan Results:\n{result}\n")
            
                # Display the raw results directly in the results_display
                self.results_display.append(result)
        
            except Exception as e:
                self.results_display.append(f"Error running custom scan: {str(e)}\n")
        else:
            self.results_display.append("Custom scan canceled or invalid input.\n")
