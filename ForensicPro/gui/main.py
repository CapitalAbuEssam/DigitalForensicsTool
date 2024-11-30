import sys
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel


# Set the required Qt attribute for OpenGL contexts before creating the application
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

class ForensicPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensicPro GUI")
        self.setGeometry(100, 100, 1000, 600)

        # Tab Widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Add the first feature (File Monitoring)
        self.add_file_monitor_tab()
        self.add_malware_scan_tab()
        self.add_browser_forensics_tab()
        self.add_persistence_analysis_tab()
        self.add_timeline_analysis_tab()
        self.add_memory_forensics_tab()
        self.add_packet_analysis_tab()
        self.add_process_analysis_tab()
        self.add_usb_analysis_tab()
        self.add_nmap_analysis_tab()
        self.add_metadata_extraction_tab()

    def add_file_monitor_tab(self):
        from file_monitor import FileMonitorTab
        self.tabs.addTab(FileMonitorTab(), "File Monitoring")

    def add_malware_scan_tab(self):
        from malware_scan import MalwareScanTab
        self.tabs.addTab(MalwareScanTab(), "Malware Scanning")

    def add_browser_forensics_tab(self):
        from browser_forensics import BrowserForensicsTab
        self.tabs.addTab(BrowserForensicsTab(), "Browser Forensics")

    def add_persistence_analysis_tab(self):
        from persistence_analysis import PersistenceAnalysisTab
        self.tabs.addTab(PersistenceAnalysisTab(), "Persistence Analysis")

    def add_timeline_analysis_tab(self):
        from timeline_analysis import TimelineAnalysisTab
        self.tabs.addTab(TimelineAnalysisTab(), "Timeline Analysis")

    def add_memory_forensics_tab(self):
        from memory_forensics import MemoryForensicsTab
        self.tabs.addTab(MemoryForensicsTab(), "Memory Forensics")

    def add_packet_analysis_tab(self):
        from packet_capture import PacketCaptureTab
        self.tabs.addTab(PacketCaptureTab(), "Packet Capturing")

    def add_process_analysis_tab(self):
        from process_analysis import ProcessAnalysisTab
        self.tabs.addTab(ProcessAnalysisTab(), "Process Analysis")

    def add_usb_analysis_tab(self):
        from usb_analysis import USBAnalysisTab
        self.tabs.addTab(USBAnalysisTab(), "USB Analysis")

    def add_nmap_analysis_tab(self):
        from Nmap_Analysis import LegendaryNmapTab
        self.tabs.addTab(LegendaryNmapTab(), "Nmap Analysis")

    def add_metadata_extraction_tab(self):
        from Metadata_Extraction import MetadataAnalysisTab
        self.tabs.addTab(MetadataAnalysisTab(), "Metadata Analysis")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicPro()
    window.show()
    sys.exit(app.exec_())
