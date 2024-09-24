# OutWatcher

## Overview

OutWatcher is a powerful network and DNS monitoring tool with integrated OSINT (Open-Source Intelligence) analysis using **VirusTotal** and **OTX (Open Threat Exchange)**. The application monitors outbound network connections, checks DNS queries, and performs OSINT lookups on IP addresses and domain names, providing real-time threat intelligence for your network.

### Features

- **Network Monitoring**: Tracks outbound connections and sends new IP addresses to OSINT services.
- **DNS Monitoring**: Captures DNS queries and sends new domains to OSINT services.
- **OSINT Integration**: Uses VirusTotal and OTX to gather intelligence on detected IPs and domains.
- **Real-time Alerts**: Notifies users of potential threats based on OSINT data.
- **Customizable Monitoring**: Allows users to choose between IP monitoring, DNS monitoring, or both.
- **Automatic or Manual Interface Selection**: Offers both automatic and manual selection of network interfaces for monitoring.
- **Reputation Expiration Handling**: Ensures that reputation checks have an expiration date, automatically rechecking Domains and IP addresses if they haven't been seen checked within configurable time period (e.g., 14 days) to maintain up-to-date threat intelligence.
-  **Caching and Database usage**: Reducing signifaclly the amount of queries to OSINT resources.


## Technologies Used

- **Python 3.x**: Core programming language
- **Scapy**: For DNS packet sniffing
- **Psutil**: For monitoring network connections and interface selection
- **SQLite**: For caching known IPs and domains
- **VirusTotal API**: For IP and domain intelligence
- **OTX (Open Threat Exchange) API**: For additional OSINT analysis
- **Threading**: For concurrent monitoring of network and DNS activities

## Installation

### Prerequisites

1. Python 3.x
2. pip (Python package manager)
3. Npcap driver (npcap.com) being used also in Wireshark

### Install Dependencies

```bash
pip install scapy psutil requests
```

### Clone the Repository

```bash
git clone https://github.com/nirjako/outwatcher.git
cd outwatcher
```

## Setup

1. **API Keys**: You will need API keys for VirusTotal and OTX.
   - VirusTotal: Get your API key [here](https://www.virustotal.com/gui/join-us).
   - OTX: Get your API key [here](https://otx.alienvault.com/api).

2. **Create API Key Files**:
   - Create a file named `vt.key` and place your VirusTotal API key inside.
   - Create a file named `otx.key` and place your OTX API key inside.

3. **Databases**: SQLite databases for caching domains and IPs will be automatically created (`domains.db` and `ips.db`).

## Usage

### Run the Application

```bash
python outwatcher.py [options]
```

### Stop the Application
```bash
Ctrl + C
```


**Options**:
- `--ip`: Enable IP monitoring
- `--dns`: Enable DNS monitoring
- `--vt-key`: Path to the VirusTotal API key file (default: `vt.key`)
- `--otx-key`: Path to the OTX API key file (default: `otx.key`)
- `--interface_manual`: Manually select the network interface for DNS monitoring
- `--expire`: Manually choose the expiration time of target reputation (default is 15 days)

### Examples

To run OutWatcher with both IP and DNS monitoring:

```bash
python outwatcher.py
```

To run OutWatcher with DNS monitoring only:

```bash
python outwatcher.py --dns
```

To run OutWatcher with DNS monitoring only and manual interface selection:

```bash
python outwatcher.py --dns --interface_manual
```

To run OutWatcher with 30 days expiration time for reputation:

```bash
python outwatcher.py --expire 30
```

## Project Structure

```
.
├── README.md               # Project documentation
├── outwatcher.py                 # Entry point for the application
├── ip_monitor.py           # IP monitoring logic
├── dns_monitor.py          # DNS monitoring logic
├── osint.py                # OSINT (VirusTotal and OTX) integration logic
├── vt.key                  # VirusTotal API key (not included in the repo)
├── otx.key                 # OTX API key (not included in the repo)
├── domains.db              # SQLite database for caching domains
└── ips.db                  # SQLite database for caching IPs
```

## Known Issues

- Ensure that the required API keys are valid and placed correctly in the respective key files.
- Some network interfaces may not work with DNS sniffing if permissions are not granted (on Linux, consider running with `sudo`).
- Large networks may require adjustments to the monitoring frequency for optimal performance.

## Troubleshooting

- If you encounter permission issues, try running the application with elevated privileges.
- Ensure your firewall is not blocking the application's network access.
- Check that the necessary Python packages are installed correctly.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [VirusTotal](https://www.virustotal.com/) for providing the API for threat intelligence.
- [AlienVault OTX](https://otx.alienvault.com/) for the Open Threat Exchange platform.
- All the contributors who have helped to improve OutWatcher.
