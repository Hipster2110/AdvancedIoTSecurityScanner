import nmap
import scapy.all as scapy
import requests
import pandas as pd
import smtplib
from email.message import EmailMessage
from sklearn.preprocessing import MinMaxScaler
import numpy as np

# Fetch latest vulnerabilities from CVE database
def fetch_cve_data():
    url = "https://cve.circl.lu/api/last"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return []

# Function to scan network for IoT devices
def scan_network(network_range):
    print(f"Scanning {network_range} for IoT devices...\n")
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for packet in answered_list:
        device = {"IP": packet[1].psrc, "MAC": packet[1].hwsrc}
        devices.append(device)

    return devices

# Function to scan ports and services of discovered IoT devices
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-65535', '-sV')  # Scan all ports
    open_ports = {}

    for port in scanner[ip]['tcp']:
        if scanner[ip]['tcp'][port]['state'] == 'open':
            open_ports[port] = scanner[ip]['tcp'][port]['name']

    return open_ports

# AI-based risk scoring for IoT devices
def calculate_risk_score(open_ports, cve_data):
    risk_scores = []
    
    for port, service in open_ports.items():
        port_risk = 0
        for cve in cve_data:
            if service.lower() in cve.get("summary", "").lower():
                port_risk += 1
        
        risk_scores.append(port_risk)

    if risk_scores:
        scaler = MinMaxScaler(feature_range=(1, 10))  # Scale risk between 1-10
        scores = np.array(risk_scores).reshape(-1, 1)
        normalized_scores = scaler.fit_transform(scores).flatten()
        return round(np.mean(normalized_scores), 2)
    
    return 1  # Default low risk if no CVEs found

# Function to send email alert for high-risk devices
def send_alert(ip, mac, risk_score):
    if risk_score < 7:
        return  # Only send alerts for high-risk devices

    sender_email = "your_email@gmail.com"  # Replace with your email
    receiver_email = "admin_email@gmail.com"  # Replace with recipient's email
    password = "your_password"  # Use an app password for security

    msg = EmailMessage()
    msg.set_content(f"⚠️ High-Risk IoT Device Detected!\n\nIP: {ip}\nMAC: {mac}\nRisk Score: {risk_score}/10\nPlease investigate immediately.")
    msg["Subject"] = "🚨 IoT Security Alert"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print(f"📧 Alert sent for high-risk device: {ip}")
    except Exception as e:
        print(f"❌ Email alert failed: {e}")

# Main function
if __name__ == "__main__":
    network = "192.168.1.1/24"  # Change this to your network range
    devices = scan_network(network)
    cve_data = fetch_cve_data()

    print("\nDiscovered IoT Devices:")
    for device in devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}")
        open_ports = scan_ports(device["IP"])
        print(f"Open Ports & Services: {open_ports}")

        risk_score = calculate_risk_score(open_ports, cve_data)
        print(f"🛑 Risk Score: {risk_score}/10\n")

        if risk_score >= 7:
            send_alert(device["IP"], device["MAC"], risk_score)

    # Save results to a file
    with open("iot_security_scan_results.txt", "w") as file:
        for device in devices:
            file.write(f"IP: {device['IP']}, MAC: {device['MAC']}\n")
            open_ports = scan_ports(device["IP"])
            risk_score = calculate_risk_score(open_ports, cve_data)
            file.write(f"Open Ports & Services: {open_ports}\n")
            file.write(f"🛑 Risk Score: {risk_score}/10\n\n")

    print("\n✅ Scan complete! Results saved in 'iot_security_scan_results.txt'")
