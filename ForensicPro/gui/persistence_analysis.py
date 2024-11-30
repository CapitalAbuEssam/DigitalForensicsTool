import os
import subprocess
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit

class PersistenceAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())

        # Title
        self.title = QLabel("Persistence Mechanism Analysis")
        self.layout().addWidget(self.title)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setPlainText("Analysis Results will appear here...\n")
        self.layout().addWidget(self.results_display)

        # Analyze Button
        self.analyze_button = QPushButton("Analyze Persistence Mechanisms")
        self.analyze_button.clicked.connect(self.analyze_persistence)
        self.layout().addWidget(self.analyze_button)

    def analyze_persistence(self):
        self.results_display.clear()
        self.results_display.append("Starting persistence mechanism analysis...\n")
        
        # Perform the analysis
        self.analyze_cron_jobs()
        self.analyze_autostart_services()

    def analyze_cron_jobs(self):
        self.results_display.append("\n--- Analyzing Cron Jobs ---\n")
        
        try:
            # System-wide cron jobs
            cron_files = ["/etc/crontab"] + [f"/etc/cron.{d}" for d in ["hourly", "daily", "weekly", "monthly"]]
            for cron_file in cron_files:
                if os.path.exists(cron_file):
                    self.results_display.append(f"Checking {cron_file}:\n")
                    with open(cron_file, "r") as file:
                        lines = file.readlines()
                        cron_content = "\n".join([line.strip() for line in lines if line.strip() and not line.startswith("#")])
                        if cron_content:
                            self.results_display.append(f"{cron_content}\n")
                        else:
                            self.results_display.append("No entries found\n")
                else:
                    self.results_display.append(f"{cron_file} does not exist.\n")

            # User-specific cron jobs
            users = [user.strip() for user in subprocess.getoutput("cut -d: -f1 /etc/passwd").split("\n")]
            for user in users:
                try:
                    cron_output = subprocess.getoutput(f"sudo -u {user} crontab -l")
                    if cron_output:
                        self.results_display.append(f"\nCron jobs for user {user}:\n{cron_output}\n")
                    else:
                        self.results_display.append(f"\nNo cron jobs for user {user}\n")
                except Exception as e:
                    self.results_display.append(f"\nError checking cron jobs for {user}: {e}\n")
        except Exception as e:
            self.results_display.append(f"\nError analyzing cron jobs: {e}\n")

    def analyze_autostart_services(self):
        self.results_display.append("\n--- Analyzing Autostart Services ---\n")
        
        try:
            # Check systemd services
            systemd_services = subprocess.getoutput("systemctl list-unit-files --type=service")
            self.results_display.append(f"\nSystemd Services:\n{systemd_services}\n")

            # Check rc.local
            rc_local_path = "/etc/rc.local"
            if os.path.exists(rc_local_path):
                self.results_display.append(f"\nChecking {rc_local_path}:\n")
                with open(rc_local_path, "r") as file:
                    lines = file.readlines()
                    rc_content = "\n".join([line.strip() for line in lines if line.strip() and not line.startswith("#")])
                    if rc_content:
                        self.results_display.append(f"{rc_content}\n")
                    else:
                        self.results_display.append("No entries found\n")
            else:
                self.results_display.append(f"\n{rc_local_path} not found.\n")

            # Check init.d scripts
            initd_path = "/etc/init.d/"
            if os.path.isdir(initd_path):
                self.results_display.append(f"\nChecking init.d scripts in {initd_path}:\n")
                initd_files = os.listdir(initd_path)
                if initd_files:
                    for script in initd_files:
                        self.results_display.append(f"  - {script}\n")
                else:
                    self.results_display.append("No init.d scripts found.\n")
            else:
                self.results_display.append(f"\n{initd_path} directory not found.\n")
        except Exception as e:
            self.results_display.append(f"\nError analyzing autostart services: {e}\n")
