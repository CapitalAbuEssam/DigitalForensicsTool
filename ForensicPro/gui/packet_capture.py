from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QFileDialog, QLabel, QProgressBar, QComboBox
from PyQt5.QtCore import pyqtSignal, QObject, QTimer, Qt
import os
import time
import subprocess
import pyshark  # Used for validating pcap files
from threading import Thread


class Worker(QObject):
    capture_finished_signal = pyqtSignal(str)
    check_file_signal = pyqtSignal(bool)

    def run_packet_capture(self, duration, save_path, interface):
        try:
            self.capture_finished_signal.emit(f"Starting packet capture for {duration} seconds...\n")

            command = f"sudo tcpdump -i {interface} -w {save_path} -n -U &"  # Adding -U to ensure immediate write
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            start_time = time.time()
            elapsed_time = 0
            while elapsed_time < duration:
                elapsed_time = time.time() - start_time
                progress = int((elapsed_time / duration) * 100)
                self.capture_finished_signal.emit(f"Progress: {progress}%")
                time.sleep(0.1)

            # Gracefully terminate tcpdump process after capture duration is over
            process.terminate()
            process.wait()

            stdout, stderr = process.communicate()

            if stderr:
                self.capture_finished_signal.emit(f"Error: {stderr.decode()}\n")
            else:
                self.capture_finished_signal.emit("Packet capture completed successfully.\n")

            # Ensure progress bar reaches 100%
            self.capture_finished_signal.emit(f"Progress: 100%\n")

            # Wait for the file to be finalized and check if it exists
            if os.path.exists(save_path) and os.path.getsize(save_path) > 0:
                # Validate the pcap file
                if self.is_valid_pcap(save_path):
                    self.check_file_signal.emit(True)
                else:
                    self.check_file_signal.emit(False)
            else:
                self.check_file_signal.emit(False)

        except Exception as e:
            self.capture_finished_signal.emit(f"Error during capture: {str(e)}")

    def is_valid_pcap(self, file_path):
        try:
            cap = pyshark.FileCapture(file_path, only_summaries=True)
            return True
        except Exception as e:
            return False


class PacketCaptureTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Capture Duration Input
        self.duration_label = QLabel("Enter Capture Duration (in seconds):")
        self.layout().addWidget(self.duration_label)

        self.duration_input = QLineEdit(self)
        self.layout().addWidget(self.duration_input)

        # Capture Location Input
        self.save_label = QLabel("Choose where to save the .pcap file:")
        self.layout().addWidget(self.save_label)

        self.save_button = QPushButton("Select Save Location")
        self.save_button.clicked.connect(self.select_save_location)
        self.layout().addWidget(self.save_button)

        self.selected_path_label = QLabel("No path selected.")
        self.layout().addWidget(self.selected_path_label)

        # Interface Selection
        self.interface_label = QLabel("Select Network Interface:")
        self.layout().addWidget(self.interface_label)

        self.interface_dropdown = QComboBox(self)
        self.layout().addWidget(self.interface_dropdown)
        self.populate_interfaces()

        # Start Packet Capture Button
        self.capture_button = QPushButton("Start Packet Capture")
        self.capture_button.clicked.connect(self.start_packet_capture)
        self.layout().addWidget(self.capture_button)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.layout().addWidget(self.progress_bar)

        # Timer to check for file creation
        self.file_check_timer = QTimer(self)
        self.file_check_timer.timeout.connect(self.check_for_file)
        self.file_check_timer.setInterval(1000)  # Check every second
        self.file_check_timer.start()

        # Worker setup
        self.worker = Worker()

        # Connect worker signals to the appropriate slots
        self.worker.capture_finished_signal.connect(self.on_capture_finished)
        self.worker.check_file_signal.connect(self.on_file_created)

    def populate_interfaces(self):
        # Use `ifconfig` or `ip link` to populate available interfaces
        interfaces = self.get_network_interfaces()
        self.interface_dropdown.addItems(interfaces)

    def get_network_interfaces(self):
        # Returns a list of available network interfaces (using `ifconfig` or `ip link`)
        interfaces = []
        try:
            result = subprocess.check_output(['ip', 'link'], stderr=subprocess.STDOUT).decode()
            interfaces = [line.split(':')[1].strip() for line in result.split('\n') if ':' in line]
        except Exception as e:
            self.results_display.append(f"Error getting interfaces: {str(e)}")
        return interfaces

    def select_save_location(self):
        # Let user select location to save the .pcap file
        save_path = QFileDialog.getSaveFileName(self, "Save Packet Capture", "", "PCAP Files (*.pcap)")[0]
        if save_path:
            self.selected_path_label.setText(f"Selected save location: {save_path}")
            self.save_path = save_path
        else:
            self.selected_path_label.setText("No path selected.")

    def start_packet_capture(self):
        # Get the duration and validate it
        duration = self.duration_input.text()
        if not duration.isdigit():
            self.results_display.append("Please enter a valid duration in seconds.\n")
            return
        duration = int(duration)

        # Ensure save path and interface are selected
        if not hasattr(self, 'save_path') or not self.save_path:
            self.results_display.append("Please select a save location for the capture.\n")
            return
        if not self.interface_dropdown.currentText():
            self.results_display.append("Please select a network interface.\n")
            return

        # Disable UI to prevent multiple captures
        self.capture_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.duration_input.setEnabled(False)
        self.interface_dropdown.setEnabled(False)

        # Clear the progress bar and previous results before starting a new capture
        self.results_display.clear()
        self.progress_bar.setValue(0)

        # Start the packet capture in a separate thread to avoid freezing the UI
        self.thread = Thread(target=self.worker.run_packet_capture, args=(duration, self.save_path, self.interface_dropdown.currentText()))
        self.thread.start()

    def on_capture_finished(self, message):
        # This method is called when the packet capture is finished
        self.results_display.append(message)

    def on_file_created(self, is_created):
        # This method is called when the file is created
        if is_created:
            self.results_display.append(f"File saved successfully at {self.save_path}")
            self.reset_ui()
        else:
            self.results_display.append(f"Error: The file could not be saved properly.\n")

    def check_for_file(self):
        """ Check if the file exists and validate it. This will be called every second """
        if hasattr(self, 'save_path') and self.save_path:
            if os.path.exists(self.save_path) and os.path.getsize(self.save_path) > 0:
                if self.worker.is_valid_pcap(self.save_path):
                    self.on_file_created(True)
                else:
                    self.on_file_created(False)

    def reset_ui(self):
        # Reset UI elements for the next capture
        self.capture_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.duration_input.setEnabled(True)
        self.interface_dropdown.setEnabled(True)
        self.progress_bar.setValue(0)
        self.selected_path_label.setText("No path selected.")
        self.save_path = None
        self.results_display.clear()
