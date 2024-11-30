import psutil
import os
import sqlite3
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QProgressBar, QMessageBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal


class ScanWorker(QThread):
    scan_progress = pyqtSignal(int)
    scan_update = pyqtSignal(str)
    scan_finished = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

    def run(self):
        self.scan_chrome()
        self.scan_firefox()
        self.scan_finished.emit()

    def scan_chrome(self):
        chrome_path = os.path.expanduser("~/.config/google-chrome/Default/History")
        if os.path.exists(chrome_path):
            self.scan_update.emit("Found Chrome history. Extracting...\n")
            self.extract_chrome_data(chrome_path)
        else:
            self.scan_update.emit("Chrome history not found.\n")
        self.scan_progress.emit(50)

    def extract_chrome_data(self, history_path):
        try:
            self.scan_update.emit("Loading Chrome data...\n")
            conn = sqlite3.connect(history_path)
            cursor = conn.cursor()

            self.scan_update.emit("\nChrome Browsing History:\n")
            query = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10"
            cursor.execute(query)
            for row in cursor.fetchall():
                self.scan_update.emit(f"URL: {row[0]}, Title: {row[1]}\n")

            self.scan_update.emit("\nChrome Download History:\n")
            query = "SELECT current_path, start_time FROM downloads ORDER BY start_time DESC LIMIT 10"
            cursor.execute(query)
            for row in cursor.fetchall():
                self.scan_update.emit(f"Path: {row[0]}, Time: {row[1]}\n")

            conn.close()
        except Exception as e:
            self.scan_update.emit(f"Error extracting Chrome data: {e}\n")

    def scan_firefox(self):
        firefox_profile_dir = os.path.expanduser("~/.mozilla/firefox/")
        if os.path.exists(firefox_profile_dir):
            self.scan_update.emit("Found Firefox profiles. Extracting...\n")
            self.extract_firefox_data(firefox_profile_dir)
        else:
            self.scan_update.emit("Firefox data not found.\n")
        self.scan_progress.emit(100)

    def extract_firefox_data(self, firefox_profile_dir):
        try:
            for profile in os.listdir(firefox_profile_dir):
                if profile.endswith(".default") or profile.endswith(".default-esr"):
                    history_path = os.path.join(firefox_profile_dir, profile, "places.sqlite")
                    cookies_path = os.path.join(firefox_profile_dir, profile, "cookies.sqlite")

                    if os.path.exists(history_path):
                        self.scan_update.emit(f"Found Firefox history in {history_path}. Extracting...\n")
                        self.extract_firefox_history(history_path)
                    else:
                        self.scan_update.emit(f"Firefox history not found in {history_path}.\n")

                    if os.path.exists(cookies_path):
                        self.scan_update.emit(f"Found Firefox cookies in {cookies_path}. Extracting...\n")
                        self.extract_firefox_cookies(cookies_path)
                    else:
                        self.scan_update.emit(f"Firefox cookies not found in {cookies_path}.\n")
        except Exception as e:
            self.scan_update.emit(f"Error extracting Firefox data: {e}\n")

    def extract_firefox_history(self, history_path):
        try:
            self.scan_update.emit("Loading Firefox browsing history...\n")
            conn = sqlite3.connect(history_path)
            cursor = conn.cursor()

            self.scan_update.emit("\nFirefox Browsing History:\n")
            query = "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 10"
            cursor.execute(query)
            for row in cursor.fetchall():
                self.scan_update.emit(f"URL: {row[0]}, Title: {row[1]}\n")

            conn.close()
        except Exception as e:
            self.scan_update.emit(f"Error extracting Firefox history: {e}\n")

    def extract_firefox_cookies(self, cookies_path):
        try:
            self.scan_update.emit("Loading Firefox cookies...\n")
            conn = sqlite3.connect(cookies_path)
            cursor = conn.cursor()

            self.scan_update.emit("\nFirefox Cookies:\n")
            query = "SELECT name, value, host FROM moz_cookies LIMIT 10"
            cursor.execute(query)
            for row in cursor.fetchall():
                self.scan_update.emit(f"Name: {row[0]}, Value: {row[1]}, Host: {row[2]}\n")

            conn.close()
        except Exception as e:
            self.scan_update.emit(f"Error extracting Firefox cookies: {e}\n")


class BrowserForensicsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        self.title = QLabel("Browser Forensics: Extract History, Cookies, and Downloads")
        self.layout().addWidget(self.title)

        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.layout().addWidget(self.results_display)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.check_browsers_and_start_scan)
        self.layout().addWidget(self.scan_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.layout().addWidget(self.progress_bar)

        self.scan_thread = None

    def check_browsers_and_start_scan(self):
        """Check if browsers are running, and forcefully close them if necessary."""
        if self.is_browser_running("chrome") or self.is_browser_running("firefox"):
            self.show_browser_force_close_prompt()
        else:
            self.start_scan()

    def is_browser_running(self, browser_name):
        """Check if a given browser is currently running."""
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if proc.info['name'].lower() == browser_name.lower():
                return True
        return False

    def show_browser_force_close_prompt(self):
        """Show a prompt asking the user to close or forcefully terminate the browser."""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Chrome or Firefox is still running.")
        msg.setInformativeText("This tool will forcefully close Chrome and Firefox before scanning. Do you want to proceed?")
        msg.setWindowTitle("Force Close Browsers")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        result = msg.exec_()

        if result == QMessageBox.Yes:
            self.force_close_browser("chrome")
            self.force_close_browser("firefox")
            self.start_scan()

    def force_close_browser(self, browser_name):
        """Forcefully close a browser by terminating its processes."""
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if proc.info['name'].lower() == browser_name.lower():
                try:
                    proc.terminate()  # Attempt to terminate the process
                    proc.wait(timeout=3)  # Wait for process to terminate
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    pass
                except psutil.TimeoutExpired:
                    pass

    def start_scan(self):
        """Start the scan if browsers are closed."""
        self.results_display.clear()
        self.results_display.append("Starting browser forensics...\n")

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.scan_thread = ScanWorker(self)
        self.scan_thread.scan_progress.connect(self.update_progress)
        self.scan_thread.scan_update.connect(self.update_results)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        self.scan_thread.start()

    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_bar.setValue(value)

    def update_results(self, text):
        """Append new results to the QTextEdit widget."""
        self.results_display.append(text)

    def scan_finished(self):
        """Called when the scanning is done."""
        self.progress_bar.setVisible(False)
        self.results_display.append("\nScanning finished!")
