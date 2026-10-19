# PCAP Network Analyzer

A Python-based cybersecurity tool that analyzes PCAP (packet capture) files and generates network traffic reports using Scapy.

## Features

- Analyze a single PCAP file or a directory of PCAP files
- Identify IP traffic and network protocols
- Track source and destination IP addresses
- Identify observed network ports
- Summarize packet counts and traffic statistics
- Generate readable text reports
- Optionally export analysis results as JSON
- Specify a custom output directory for reports

## Technologies

- Python 3
- Scapy
- TCP/IP networking
- PCAP packet analysis
- JSON
- Command-line argument parsing

## Requirements

- Python 3
- Scapy

## Installation

Install the required dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

Display the available command-line options:

```bash
python "PCAP Network analyzer.py" --help
```

Analyze a PCAP file:

```bash
python "PCAP Network analyzer.py" sample.pcap
```

Analyze PCAP files in a directory:

```bash
python "PCAP Network analyzer.py" ./pcaps
```

Generate text and JSON reports:

```bash
python "PCAP Network analyzer.py" ./pcaps --json
```

Choose a custom output directory:

```bash
python "PCAP Network analyzer.py" ./pcaps --output results
```

Replace the example file or directory paths with paths to your own authorized packet captures.

## Cybersecurity Skills Demonstrated

- Python scripting and automation
- Network traffic analysis
- TCP/IP protocols
- Packet capture analysis
- Data processing and reporting
- Command-line tool development
- JSON output and file handling

## Testing

The analyzer was tested locally using a sample PCAP file containing 142,966 packets.

The test successfully generated a text report containing:
- Total packet and byte counts
- Protocol statistics
- Top source and destination IP addresses
- Destination port statistics
- Network connection summaries

The sample PCAP file and generated report are not included in this repository to avoid publishing potentially sensitive network information.

## Disclaimer

This project is intended for educational use and authorized network analysis only. Analyze only packet captures you have permission to access.
