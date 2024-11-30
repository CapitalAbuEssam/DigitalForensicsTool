import os
import glob
import pandas as pd
from datetime import datetime
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog

class TimelineAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Title
        self.title = QLabel("Timeline Analysis")
        self.layout().addWidget(self.title)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        # Analyze Button
        self.analyze_button = QPushButton("Generate Timeline")
        self.analyze_button.clicked.connect(self.generate_timeline)
        self.layout().addWidget(self.analyze_button)

        # Export Button
        self.export_button = QPushButton("Export Timeline to CSV")
        self.export_button.clicked.connect(self.export_timeline)
        self.export_button.setEnabled(False)
        self.layout().addWidget(self.export_button)

        self.timeline_data = None  # Store timeline data for export

    def generate_timeline(self):
        self.results_display.clear()
        self.results_display.append("Generating forensic timeline...\n")

        try:
            timeline_entries = []

            # File Events
            self.results_display.append("Processing file events...\n")
            file_events = self.load_file_events()
            timeline_entries.extend(file_events)

            # Process Events
            self.results_display.append("Processing process activity...\n")
            process_events = self.load_process_events()
            timeline_entries.extend(process_events)

            # System Logs
            self.results_display.append("Processing system logs...\n")
            log_events = self.load_system_logs()
            timeline_entries.extend(log_events)

            # Sort by timestamp
            self.results_display.append("Sorting events...\n")
            self.timeline_data = pd.DataFrame(timeline_entries)
            self.timeline_data.sort_values("timestamp", inplace=True)

            # Display results
            self.results_display.append(self.timeline_data.to_string(index=False))
            self.export_button.setEnabled(True)
        except Exception as e:
            self.results_display.append(f"Error generating timeline: {e}\n")

    def load_file_events(self):
        try:
            file_events_path = "logs/file_events.log"  # Update based on actual path or config
            if not os.path.exists(file_events_path):
                return []

            with open(file_events_path, "r") as file:
                lines = file.readlines()
                events = [
                    {"timestamp": datetime.strptime(line.split(" - ")[0], "%Y-%m-%d %H:%M:%S"),
                     "event_type": "File Event",
                     "description": line.strip()}
                    for line in lines
                ]
            return events
        except Exception as e:
            self.results_display.append(f"Error loading file events: {e}\n")
            return []

    def load_process_events(self):
        try:
            process_events_path = "logs/process_monitoring.log"  # Update based on actual path or config
            if not os.path.exists(process_events_path):
                return []

            with open(process_events_path, "r") as file:
                lines = file.readlines()
                events = [
                    {"timestamp": datetime.strptime(line.split(" - ")[0], "%Y-%m-%d %H:%M:%S"),
                     "event_type": "Process Event",
                     "description": line.strip()}
                    for line in lines
                ]
            return events
        except Exception as e:
            self.results_display.append(f"Error loading process events: {e}\n")
            return []

    def load_system_logs(self):
        try:
            log_files = self.find_log_files()
            events = []

            for log_file in log_files:
                if not os.path.exists(log_file):
                    continue

                with open(log_file, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        try:
                            # Adjusted timestamp format for syslog
                            parts = line.split(" ", 1)
                            if len(parts) < 2:
                                continue  # Skip lines that don't have at least a timestamp and message

                            timestamp, message = parts
                            
                            # Debugging to check the timestamp format
                            self.results_display.append(f"Debug: Timestamp: {timestamp} Message: {message}")

                            try:
                                # Try to parse timestamp (format for logs with date and time)
                                timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                            except ValueError:
                                try:
                                    # If it fails, try without timezone information
                                    timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
                                except ValueError:
                                    self.results_display.append(f"Error parsing timestamp: {timestamp}")
                                    continue  # Skip lines with invalid timestamps

                            events.append({
                                "timestamp": timestamp,
                                "event_type": "System Log",
                                "description": message.strip()
                            })
                        except ValueError:
                            continue  # Skip lines with incorrect formatting
            return events
        except Exception as e:
            self.results_display.append(f"Error loading system logs: {e}\n")
            return []

    def find_log_files(self):
        """
        Dynamically find relevant log files for the system.
        """
        log_files = []

        # Common log paths for most Linux systems
        common_log_paths = [
            "/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/dmesg"
        ]

        # Check the existence of each log file and add it to the list
        for path in common_log_paths:
            if os.path.exists(path):
                log_files.append(path)

        # Optional: If logs are elsewhere, use glob to find additional log files
        additional_logs = glob.glob("/var/log/*.log")
        log_files.extend(additional_logs)

        return log_files

    def export_timeline(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Timeline", "", "CSV Files (*.csv)")
            if file_path:
                self.timeline_data.to_csv(file_path, index=False)
                self.results_display.append(f"Timeline exported to {file_path}\n")
        except Exception as e:
            self.results_display.append(f"Error exporting timeline: {e}\n")
