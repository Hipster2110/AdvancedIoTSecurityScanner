# AdvancedIoTSecurityScanner
# Advanced IoT Security Scanner

## Overview
The **Advanced IoT Security Scanner** is a Python-based tool designed to scan a network for IoT devices, detect open ports and services, assess risk levels using AI-based scoring, and fetch the latest vulnerabilities from the CVE database. It also provides automated email alerts for high-risk devices.

## Features
- **Network Scanning**: Detects IoT devices on a specified network range using ARP requests.
- **Port Scanning**: Identifies open ports and services on discovered devices using Nmap.
- **CVE Vulnerability Lookup**: Fetches the latest vulnerabilities from the CVE database.
- **AI-Based Risk Scoring**: Uses machine learning techniques to assign a risk score to devices.
- **Automated Email Alerts**: Sends alerts for high-risk devices (risk score >= 7).
- **Results Logging**: Saves scan results to `iot_security_scan_results.txt`.

## Prerequisites
Ensure you have the following dependencies installed before running the script:

- **Python 3.x**
- **Scapy** (`pip install scapy`)
- **Nmap** (`apt install nmap` or `brew install nmap`)
- **python-nmap** (`pip install python-nmap`)
- **Requests** (`pip install requests`)
- **Pandas** (`pip install pandas`)
- **Scikit-learn** (`pip install scikit-learn`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Hipster2110/AdvancedIoTSecurityScanner.git
   cd AdvancedIoTSecurityScanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   sudo python advanced_iot_scanner.py
   ```
   > **Note:** Running as **root** is required for network scanning.

## Usage
1. Update the script with your email credentials for alerts.
2. Change the network range in the script (default: `192.168.1.1/24`).
3. Run the script, and it will:
   - Detect IoT devices.
   - Scan for open ports and services.
   - Fetch CVE vulnerabilities.
   - Calculate risk scores.
   - Send email alerts if necessary.
   - Save results to `iot_security_scan_results.txt`.

## Example Output
```
Scanning 192.168.1.1/24 for IoT devices...

Discovered IoT Devices:
IP: 192.168.1.10, MAC: AA:BB:CC:DD:EE:FF
Open Ports & Services: {22: 'ssh', 80: 'http'}
🛑 Risk Score: 8.5/10
📧 Alert sent for high-risk device: 192.168.1.10

✅ Scan complete! Results saved in 'iot_security_scan_results.txt'
```

## Known Issues
- Requires **sudo/root** privileges for full functionality.
- Email alerts require configuring a secure **app password**.
- Large network scans may take time.
- Ensure **Nmap** is installed before running the script.

## Future Enhancements
- Add **device fingerprinting** to detect IoT device types.
- Implement **automatic exploit suggestions**.
- Provide **CSV and JSON export options**.
- Add **multi-threading** for faster scanning.

## License
This project is licensed under the MIT License.

## Author
Developed by **Hipster2110**. Contributions and feedback are welcome!

## Repository Link
[GitHub Repository](https://github.com/Hipster2110/AdvancedIoTSecurityScanner.git)

## Disclaimer
This tool is intended for **ethical security testing** only. Do not use it on netwo
