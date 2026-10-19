#!/usr/bin/env python3
"""
PCAP Network Analyzer

Parses PCAP files with Scapy and produces network traffic statistics.
Intended for educational use and authorized network analysis.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, rdpcap


def process_pcap(file_path):
    """Parse a PCAP and return structured traffic statistics."""
    packets = rdpcap(str(file_path))

    connections = defaultdict(lambda: {"packets": 0, "bytes": 0})
    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    destination_ports = Counter()
    observed_ports = set()
    total_bytes = 0

    for pkt in packets:
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_length = len(pkt)
        total_bytes += packet_length

        source_ips[src_ip] += 1
        destination_ips[dst_ip] += 1

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol_name = "TCP"

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol_name = "UDP"

        else:
            src_port = None
            dst_port = None
            protocol_name = f"IP-{ip_layer.proto}"

        protocols[protocol_name] += 1

        if src_port is not None:
            observed_ports.add(src_port)

        if dst_port is not None:
            observed_ports.add(dst_port)
            destination_ports[dst_port] += 1

        connection_key = (
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol_name,
        )

        connections[connection_key]["packets"] += 1
        connections[connection_key]["bytes"] += packet_length

    return {
        "packet_count": len(packets),
        "analyzed_ip_packets": sum(protocols.values()),
        "total_bytes": total_bytes,
        "protocols": dict(protocols),
        "source_ips": dict(source_ips),
        "destination_ips": dict(destination_ips),
        "destination_ports": dict(destination_ports),
        "observed_ports": sorted(observed_ports),
        "connections": {
            _connection_to_string(key): value
            for key, value in connections.items()
        },
    }


def _connection_to_string(connection):
    """Convert a connection tuple into a readable string."""
    src_ip, src_port, dst_ip, dst_port, protocol = connection

    source = (
        f"{src_ip}:{src_port}"
        if src_port is not None
        else src_ip
    )

    destination = (
        f"{dst_ip}:{dst_port}"
        if dst_port is not None
        else dst_ip
    )

    return f"{source} -> {destination} ({protocol})"


def generate_text_report(file_path, analysis, output_dir):
    """Write a human-readable analysis report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    report_file = output_dir / f"{file_path.stem}_report.txt"

    with report_file.open("w", encoding="utf-8") as report:
        report.write(
            f"=== PCAP Report for {file_path.name} ===\n\n"
        )

        report.write(
            f"Total Packets: "
            f"{analysis['packet_count']}\n"
        )

        report.write(
            f"IP Packets Analyzed: "
            f"{analysis['analyzed_ip_packets']}\n"
        )

        report.write(
            f"Total Bytes: "
            f"{analysis['total_bytes']}\n\n"
        )

        report.write("Protocols:\n")
        report.write("=" * 40 + "\n")

        for protocol, count in sorted(
            analysis["protocols"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            report.write(
                f"{protocol}: {count} packets\n"
            )

        report.write("\nTop Source IPs:\n")
        report.write("=" * 40 + "\n")

        for ip, count in _top_items(
            analysis["source_ips"]
        ):
            report.write(
                f"{ip}: {count} packets\n"
            )

        report.write("\nTop Destination IPs:\n")
        report.write("=" * 40 + "\n")

        for ip, count in _top_items(
            analysis["destination_ips"]
        ):
            report.write(
                f"{ip}: {count} packets\n"
            )

        report.write("\nTop Destination Ports:\n")
        report.write("=" * 40 + "\n")

        for port, count in _top_items(
            analysis["destination_ports"]
        ):
            report.write(
                f"{port}: {count} packets\n"
            )

        report.write("\nObserved Ports:\n")
        report.write("=" * 40 + "\n")

        for port in analysis["observed_ports"]:
            report.write(f"{port}\n")

        report.write("\nConnections:\n")
        report.write("=" * 40 + "\n")

        for connection, stats in (
            analysis["connections"].items()
        ):
            report.write(
                f"{connection}\n"
                f"  Packets: {stats['packets']}\n"
                f"  Bytes: {stats['bytes']}\n\n"
            )

    return report_file


def generate_json_report(file_path, analysis, output_dir):
    """Write analysis results as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)

    report_file = (
        output_dir / f"{file_path.stem}_report.json"
    )

    with report_file.open("w", encoding="utf-8") as report:
        json.dump(analysis, report, indent=2)

    return report_file


def _top_items(items, limit=10):
    """Return the most frequently observed items."""
    return sorted(
        items.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:limit]


def find_pcap_files(path):
    """Return PCAP files from a file or directory."""

    if path.is_file():
        return [
            path
        ] if path.suffix.lower() == ".pcap" else []

    return sorted(
        file
        for file in path.iterdir()
        if file.is_file()
        and file.suffix.lower() == ".pcap"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze PCAP files and generate "
            "network traffic reports."
        )
    )

    parser.add_argument(
        "path",
        type=Path,
        help=(
            "Path to a PCAP file or directory "
            "containing PCAP files."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("reports"),
        help=(
            "Directory for generated reports "
            "(default: reports)."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Also generate a JSON report.",
    )

    args = parser.parse_args()

    if not args.path.exists():
        parser.error(
            f"Path does not exist: {args.path}"
        )

    pcap_files = find_pcap_files(args.path)

    if not pcap_files:
        parser.error(
            "No .pcap files found at the specified path."
        )

    print(
        f"[+] Found {len(pcap_files)} PCAP file(s)."
    )

    for pcap_file in pcap_files:
        print(f"[+] Processing: {pcap_file}")

        try:
            analysis = process_pcap(pcap_file)

            text_report = generate_text_report(
                pcap_file,
                analysis,
                args.output,
            )

            print(
                f"    Report: {text_report}"
            )

            if args.json:
                json_report = generate_json_report(
                    pcap_file,
                    analysis,
                    args.output,
                )

                print(
                    f"    JSON:   {json_report}"
                )

        except Exception as exc:
            print(
                f"[!] Failed to process "
                f"{pcap_file}: {exc}"
            )


if __name__ == "__main__":
    main()