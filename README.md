# outwatcher
# Network and DNS Monitoring Tool with OSINT Integration

## Overview

This project is a network and DNS monitoring tool with integrated OSINT (Open-Source Intelligence) analysis using **VirusTotal** and **OTX (Open Threat Exchange)**. The application monitors outbound network connections, checks DNS queries, and performs OSINT lookups on IP addresses and domain names.

### Features
- **Network Monitoring**: Tracks outbound connections and sends new IP addresses to OSINT services.
- **DNS Monitoring**: Captures DNS queries and sends new domains to OSINT services.
- **OSINT Integration**: Uses VirusTotal and OTX to gather intelligence on detected IPs and domains.

## Technologies Used
- **Python 3.x**
- **Scapy**: For DNS packet sniffing.
- **Psutil**: For monitoring network connections.
- **SQLite**: For caching known IPs and domains.
- **VirusTotal**: For IP and domain intelligence.
- **OTX (Open Threat Exchange)**: For additional OSINT analysis.

## Installation

### Prerequisites

1. **Python 3.x**: Make sure you have Python installed.
2. **Scapy**: For DNS packet sniffing.
3. **Psutil**: For network connection monitoring.
4. **Requests**: For making API calls to VirusTotal and OTX.

### Install Dependencies

```bash
pip install scapy psutil requests

Clone the Repository
git clone https://github.com/your-repo/network-dns-monitor.git
cd network-dns-monitor

bash

git clone https://github.com/your-repo/network-dns-monitor.git
cd network-dns-monitor

Setup

    API Keys: You will need API keys for VirusTotal and OTX.
        VirusTotal: Get your API key here.
        OTX: Get your API key here.

    Create API Key Files:
        Create a file named vt.key and place your VirusTotal API key inside.
        Create a file named otx.key and place your OTX API key inside.

    Databases: SQLite databases for caching domains and IPs will be automatically created (domains.db and ips.db).

Usage
Run the Application
python main.py --ip --dns

You can run the application with various options depending on the monitoring you want to perform:

Options:
    --ip: Monitor outbound IP connections.
    --dns: Monitor DNS queries.
    --vt-key: Path to the VirusTotal API key file (default: vt.key).
    --otx-key: Path to the OTX API key file (default: otx.key).
    --interface_manual: Manually select the network interface for DNS monitoring.

Project Structure

graphql

.
├── README.md               # Project documentation
├── main.py                 # Entry point for the application
├── osint.py                # OSINT (VirusTotal and OTX) integration logic
├── dns_monitor.py          # DNS monitoring logic
├── ip_monitor.py           # IP monitoring logic
├── vt.key                  # VirusTotal API key (not included in the repo)
├── otx.key                 # OTX API key (not included in the repo)
├── domains.db              # SQLite database for caching domains
├── ips.db                  # SQLite database for caching IPs
└── ...

Known Issues

    Ensure that the required API keys are valid and placed correctly.
    Some network interfaces may not work with DNS sniffing if permissions are not granted (on Linux, consider running with sudo).

License

This project is licensed under the MIT License. See the LICENSE file for details.
Contributing

