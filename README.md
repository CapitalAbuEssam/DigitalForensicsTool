## 📌 Overview
The **Ultimate Digital Forensics & Network Security Tool** is a powerful **Python-based** forensic application built using **PyQt5**. It combines **packet capture**, **Nmap scanning**, **file hashing**, **hidden file detection**, **VirusTotal integration**, and **advanced network analysis with visualizations**.
<img width="817" alt="2" src="https://github.com/user-attachments/assets/b983ac61-1340-4406-927d-1f60119e7419" />

## 🚀 Features

### **🛡️ Network & Security Tools**
- **📡 Packet Capture**: Capture live network traffic and analyze packets.
- **🕵️ Advanced Nmap Scanning**:
  - Quick Scan
  - Advanced Scan (OS detection, services, vulnerabilities)
  - Custom Scan (User-defined options)
  - **📊 Visual Analysis**:
    - Open Ports Analysis
    - IP Distribution Graphs
    - Network Topology Mapping
  - **📋 Tabular Results**: Structured scan results in a readable format.

### **📂 File Forensics**
- **🔑 File Hashing**: Compute and verify file integrity using **SHA-256**.
- **🔎 Hidden File Search**: Identify hidden and suspicious files.
- **🦠 VirusTotal Integration**: Check file hashes against the VirusTotal database.

### **📊 Graphs & Visualizations**
- **Open Port Distribution**
- **IP Address Activity**
- **Packet Capture Summary**
- **Nmap Scan Statistics**

---

## 🏗️ Installation

### **🔧 Requirements**
Ensure you have **Python 3.8+** installed.

### **📥 Install Dependencies**
```bash
pip install PyQt5 matplotlib requests scapy python-nmap
```

## 🐧 Linux Users
For full functionality, install Nmap:

```bash
sudo apt install nmap
```
For packet capture, install Wireshark/TShark:

```bash
sudo apt install wireshark tshark
```

## 🏃‍♂️ Usage
### 🔹 Running the Tool
Run the Python script:

```bash
python main.py
```
### 🌐 Running Nmap Scans
- Click Quick Scan for a fast port scan.
- Click Advanced Scan for OS and service detection.
- Click Custom Scan, enter your Nmap options (e.g., -sS -p 80,443 192.168.1.1), and execute.

### 📡 Packet Capture
- Click Start Capture to begin monitoring traffic.
- Click Stop Capture to save packets.
- View packet details in the GUI.
  
### 📂 File Forensics
- Select a file for SHA-256 hashing.
- Run a hidden file search.
- Scan a file’s hash with VirusTotal.
  
### 📊 Viewing Graphs
- Click Show Open Ports Graph to analyze port distribution.
- Click Visualize IP Distribution for network insights.
  
## 🔥 Screenshots
<img width="621" alt="1" src="https://github.com/user-attachments/assets/56c98344-58d2-4f0c-9183-4650107bab13" />
<img width="817" alt="2" src="https://github.com/user-attachments/assets/90366039-9535-4a44-918b-47547a4978cc" />
<img width="959" alt="3" src="https://github.com/user-attachments/assets/895280a3-04b2-4e94-b635-c5d1c7f5fdad" />
<img width="992" alt="4" src="https://github.com/user-attachments/assets/173f9eb4-ed2a-42e6-948a-7eb3c6f42051" />

### 📊 Network Scan Graph
<img width="1000" alt="5" src="https://github.com/user-attachments/assets/5565e629-2175-4765-a7bd-0a45d2e1f309" />
<img width="991" alt="6" src="https://github.com/user-attachments/assets/60a5463d-1426-4cf0-ad07-5102c4bb1798" />

## 📌 Main Interface

### 🛠️ Advanced Customization

### 🛡️ Security & Privacy Considerations
- Packet capturing requires administrative privileges.
- Nmap scans may trigger firewall alerts.
- VirusTotal API should be used responsibly (consider rate limits).

### 🏗️ Future Enhancements
- **📌 Real-time Threat Detection**
- **📌 Database Integration for Scan Logs**
- **📌 Automated Malware Analysis**

### 📜 License
MIT License. Free to use but do not distribute or sell without permission.

### Developed by Muhammad Essam 🛡️ | CapitalAbuEssam
