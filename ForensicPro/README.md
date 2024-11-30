# ForensicPro

## Day 1 Progress

### Features Implemented:
1. GUI skeleton using PyQt5.
2. File Monitoring module to detect and log file events (create, modify, delete).

### How to Run:
1. Install dependencies: `pip3 install -r requirements.txt`.
2. Run the application: `python3 gui/main.py`.

### Testing:
- File Monitoring logs file events in a selected directory.

## Day 2 Progress

### Features Implemented:
1. Malware Scanning module integrated with ClamAV and YARA.
2. GUI tab for scanning directories and displaying results.

### How to Run:
1. Install ClamAV and YARA: `sudo apt install clamav yara`.
2. Update ClamAV database: `sudo freshclam`.
3. Create YARA rules in `~/ForensicPro/yara_rules/`.
4. Run the application: `python3 gui/main.py`.

### Testing:
- ClamAV: Verify using the EICAR test file.
- YARA: Create test rules and match files in the scanned directory.

## Day 3 Progress

### Features Implemented:
1. Browser Forensics module for extracting history, cookies, and downloads.
2. Supports Chrome, Chromium, and Firefox.

### How to Run:
1. Install SQLite: `sudo apt install sqlite3`.
2. Run the application: `python3 gui/main.py`.

### Testing:
- Ensure browser data paths exist.
- Test Chrome and Firefox history and cookies parsing.

## Day 4 Progress

### Features Implemented:
1. Persistence Mechanism Analysis:
   - Analyze system-wide and user-specific cron jobs.
   - Detect autostart services and scripts.

### How to Run:
1. Ensure you have Python installed.
2. Run the application: `python3 gui/main.py`.

### Testing:
- Verify cron job analysis detects valid entries.
- Confirm autostart services from systemd, rc.local, and init.d are listed

## Day 5 Progress

### Features Implemented:
1. Timeline Analysis:
   - Correlate file events, process activity, and system logs into a single chronological view.
   - Export the timeline to a CSV file for detailed analysis.

### How to Run:
1. Ensure Python dependencies (`pandas`, `PyQt5`) are installed.
2. Run the application: `python3 gui/main.py`.

### Testing:
- Verify data from file events, process monitoring, and system logs is parsed correctly.
- Confirm sorting by timestamp.
- Test export functionality.
