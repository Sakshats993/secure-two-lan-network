#!/usr/bin/env python3
"""
=============================================================================
Secure Two-LAN Network - Traffic Analyzer
=============================================================================
Real-time packet capture and analysis with security alerting.
Features:
  - Live packet capture on VLAN interfaces
  - Protocol distribution analysis
  - Suspicious traffic detection (port scans, cross-LAN bypass, rogue DHCP)
  - Flow tracking and statistics
  - Security event logging to JSON
=============================================================================
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
import datetime
import threading
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ─── Dependency Check ─────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DHCP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install: pip3 install scapy")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False

try:
    from tabulate import tabulate
    TABULATE = True
except ImportError:
    TABULATE = False

# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "interfaces": ["eth0.10", "eth0.20"],
    "log_dir": "/var/log/traffic",
    "alert_log": "/var/log/security-events/traffic-alerts.log",
    "stats_interval": 30,
    "port_scan_threshold": 10,
    "connection_rate_threshold": 50,
}

def c(text, code=""): return f"{code}{text}{Style.RESET_ALL}" if COLORAMA and code else text
def green(t): return c(t, Fore.GREEN)
def red(t): return c(t, Fore.RED)
def yellow(t): return c(t, Fore.YELLOW)
def cyan(t): return c(t, Fore.CYAN)
def blue(t): return c(t, Fore.BLUE)
def bold(t): return c(t, Style.BRIGHT)

# ─── Data Classes ─────────────────────────────────────────────────────────────
@dataclass
class PacketStats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    arp_count: int = 0
    dns_count: int = 0
    dhcp_count: int = 0
    http_count: int = 0
    https_count: int = 0
    other_count: int = 0
    blocked_attempts: int = 0

@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    severity: str
    src_ip: str
    dst_ip: str
    description: str
    interface: str

# ─── Logger ───────────────────────────────────────────────────────────────────
def setup_logging(log_dir: str) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(os.path.dirname(DEFAULT_CONFIG["alert_log"]), exist_ok=True)
    logger = logging.getLogger("traffic-analyzer")
    logger.setLevel(logging.DEBUG)
    log_file = os.path.join(log_dir,
        f"analyzer_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# ─── Main Analyzer ────────────────────────────────────────────────────────────
class TrafficAnalyzer:
    """
    Real-time traffic analyzer with security monitoring.
    Detects: cross-LAN bypass, port scans, rogue DHCP servers,
             high connection rates.
    """

    def __init__(self, interfaces: List[str], log_dir: str, daemon_mode: bool = False):
        self.interfaces = interfaces
        self.log_dir = log_dir
        self.daemon_mode = daemon_mode
        self.logger = setup_logging(log_dir)
        self.stats: Dict[str, PacketStats] = {i: PacketStats() for i in interfaces}
        self.security_events: List[SecurityEvent] = []
        self.port_scan_tracker: Dict = defaultdict(
            lambda: {"ports": set(), "first_seen": time.time()}
        )
        self.connection_rate: Dict = defaultdict(list)
        self.top_sources: Counter = Counter()
        self.top_destinations: Counter = Counter()
        self.top_protocols: Counter = Counter()
        self.running = False
        self.capture_threads: List[threading.Thread] = []
        self.start_time = time.time()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        print(f"\n{yellow('⚠️  Shutting down...')}")
        self.running = False
        self.generate_final_report()
        sys.exit(0)

    def _get_protocol(self, packet) -> str:
        if not SCAPY_AVAILABLE:
            return "unknown"
        try:
            if packet.haslayer(DHCP): return "DHCP"
            if packet.haslayer(DNS): return "DNS"
            if packet.haslayer(TCP):
                p = packet[TCP]
                if p.dport == 80 or p.sport == 80: return "HTTP"
                if p.dport == 443 or p.sport == 443: return "HTTPS"
                return "TCP"
            if packet.haslayer(UDP): return "UDP"
            if packet.haslayer(ICMP): return "ICMP"
            if packet.haslayer(ARP): return "ARP"
            return "OTHER"
        except Exception:
            return "UNKNOWN"

    def _is_cross_lan(self, src: str, dst: str) -> bool:
        return src.startswith("192.168.2.") and dst.startswith("192.168.1.")

    def _detect_port_scan(self, src: str, dst_port: int) -> bool:
        now = time.time()
        t = self.port_scan_tracker[src]
        if now - t["first_seen"] > 60:
            t["ports"] = set()
            t["first_seen"] = now
        t["ports"].add(dst_port)
        return len(t["ports"]) > DEFAULT_CONFIG["port_scan_threshold"]

    def _detect_high_rate(self, src: str) -> bool:
        now = time.time()
        self.connection_rate[src] = [t for t in self.connection_rate[src] if now - t < 60]
        self.connection_rate[src].append(now)
        return len(self.connection_rate[src]) > DEFAULT_CONFIG["connection_rate_threshold"]

    def _log_event(self, event: SecurityEvent):
        self.security_events.append(event)
        alert_log = DEFAULT_CONFIG["alert_log"]
        try:
            with open(alert_log, "a") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write event: {e}")
        sev_fn = red if event.severity == "HIGH" else yellow
        print(f"\n{red('🚨 ALERT')} [{sev_fn(event.severity)}] {event.event_type}")
        print(f"   {event.src_ip} → {event.dst_ip}: {event.description}")
        self.logger.warning(f"[{event.severity}] {event.event_type} | {event.src_ip}→{event.dst_ip}")

    def packet_callback(self, packet, interface: str = "unknown"):
        if not self.running:
            return
        stats = self.stats[interface]
        stats.total_packets += 1
        try:
            pkt_len = len(packet) if SCAPY_AVAILABLE else 0
            stats.total_bytes += pkt_len
            proto = self._get_protocol(packet)
            proto_map = {
                "TCP": "tcp_count", "UDP": "udp_count", "ICMP": "icmp_count",
                "ARP": "arp_count", "DNS": "dns_count", "DHCP": "dhcp_count",
                "HTTP": "http_count", "HTTPS": "https_count"
            }
            attr = proto_map.get(proto, "other_count")
            setattr(stats, attr, getattr(stats, attr) + 1)
            self.top_protocols[proto] += 1

            if not SCAPY_AVAILABLE or not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.top_sources[src_ip] += 1
            self.top_destinations[dst_ip] += 1

            # Cross-LAN detection
            if self._is_cross_lan(src_ip, dst_ip):
                stats.blocked_attempts += 1
                self._log_event(SecurityEvent(
                    timestamp=datetime.datetime.now().isoformat(),
                    event_type="CROSS_LAN_BYPASS_ATTEMPT",
                    severity="HIGH", src_ip=src_ip, dst_ip=dst_ip,
                    description="LAN2→LAN1 traffic (should be blocked by firewall)",
                    interface=interface
                ))

            # Port scan detection
            if packet.haslayer(TCP) and self._detect_port_scan(src_ip, packet[TCP].dport):
                unique = len(self.port_scan_tracker[src_ip]['ports'])
                self._log_event(SecurityEvent(
                    timestamp=datetime.datetime.now().isoformat(),
                    event_type="PORT_SCAN_DETECTED",
                    severity="MEDIUM", src_ip=src_ip, dst_ip=dst_ip,
                    description=f"Port scan: {unique} unique ports in 60s",
                    interface=interface
                ))

            # High connection rate
            if self._detect_high_rate(src_ip):
                rate = len(self.connection_rate[src_ip])
                self._log_event(SecurityEvent(
                    timestamp=datetime.datetime.now().isoformat(),
                    event_type="HIGH_CONNECTION_RATE",
                    severity="MEDIUM", src_ip=src_ip, dst_ip=dst_ip,
                    description=f"High rate: {rate} connections/min",
                    interface=interface
                ))

            # Rogue DHCP detection
            if packet.haslayer(DHCP):
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 2:
                        if src_ip not in ["192.168.1.1", "192.168.2.1"]:
                            self._log_event(SecurityEvent(
                                timestamp=datetime.datetime.now().isoformat(),
                                event_type="ROGUE_DHCP_SERVER",
                                severity="HIGH", src_ip=src_ip, dst_ip="255.255.255.255",
                                description=f"Unauthorized DHCP server: {src_ip}",
                                interface=interface
                            ))

        except Exception as e:
            self.logger.debug(f"Packet error: {e}")

    def print_stats_table(self):
        elapsed = time.time() - self.start_time
        print(f"\n{bold(cyan('═' * 60))}")
        print(bold(cyan(f"  📊 TRAFFIC STATS — {datetime.datetime.now().strftime('%H:%M:%S')} | {elapsed:.0f}s | {len(self.security_events)} alerts")))
        print(bold(cyan('═' * 60)))

        for iface, stats in self.stats.items():
            print(f"\n  {bold(blue(f'Interface: {iface}'))}")
            if TABULATE:
                data = [
                    ["Total Packets", f"{stats.total_packets:,}"],
                    ["Total Bytes", f"{stats.total_bytes / 1024:.1f} KB"],
                    ["TCP", f"{stats.tcp_count:,}"], ["UDP", f"{stats.udp_count:,}"],
                    ["ICMP", f"{stats.icmp_count:,}"], ["DNS", f"{stats.dns_count:,}"],
                    ["DHCP", f"{stats.dhcp_count:,}"], ["HTTP", f"{stats.http_count:,}"],
                    ["HTTPS", f"{stats.https_count:,}"],
                    ["Blocked Attempts", red(str(stats.blocked_attempts)) if stats.blocked_attempts else "0"],
                ]
                print(tabulate(data, tablefmt="rounded_grid", colalign=("left", "right")))
            else:
                print(f"    Pkts: {stats.total_packets:,} | Bytes: {stats.total_bytes/1024:.1f}KB | "
                      f"TCP: {stats.tcp_count} | UDP: {stats.udp_count} | Blocked: {stats.blocked_attempts}")

        if self.top_sources:
            print(f"\n  {bold(blue('Top 5 Sources:'))}")
            for ip, count in self.top_sources.most_common(5):
                bar = "█" * min(20, count)
                print(f"    {ip:<18} {bar} {count}")

        if self.security_events:
            print(f"\n  {bold(red('Recent Alerts:'))}")
            for evt in self.security_events[-3:]:
                fn = red if evt.severity == "HIGH" else yellow
                print(f"    [{fn(evt.severity)}] {evt.event_type}: {evt.src_ip} → {evt.dst_ip}")

        print(bold(cyan('═' * 60)))

    def generate_final_report(self):
        report = {
            "generated_at": datetime.datetime.now().isoformat(),
            "duration_seconds": time.time() - self.start_time,
            "security_events": [asdict(e) for e in self.security_events],
            "top_sources": dict(self.top_sources.most_common(20)),
            "top_protocols": dict(self.top_protocols.most_common()),
            "interfaces": {
                iface: {
                    "total_packets": s.total_packets,
                    "total_bytes": s.total_bytes,
                    "blocked_attempts": s.blocked_attempts,
                    "protocols": {
                        "tcp": s.tcp_count, "udp": s.udp_count,
                        "icmp": s.icmp_count, "dns": s.dns_count,
                        "dhcp": s.dhcp_count, "http": s.http_count,
                        "https": s.https_count, "other": s.other_count,
                    }
                }
                for iface, s in self.stats.items()
            }
        }
        report_file = os.path.join(
            self.log_dir,
            f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2)
            print(f"\n{green(f'📄 Report saved: {report_file}')}")
        except Exception as e:
            print(f"{red(f'Failed to save report: {e}')}")
        self.print_stats_table()

    def start_capture(self, interface: str):
        self.logger.info(f"Starting capture on {interface}")
        if not SCAPY_AVAILABLE:
            return
        try:
            sniff(
                iface=interface,
                prn=lambda pkt: self.packet_callback(pkt, interface),
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Capture error on {interface}: {e}")

    def print_live_stats(self):
        while self.running:
            time.sleep(DEFAULT_CONFIG["stats_interval"])
            if self.running:
                self.print_stats_table()

    def run(self):
        self.running = True
        print(f"\n{bold(cyan('╔══════════════════════════════════════════════════╗'))}")
        print(bold(cyan('║      🔍 Secure LAN Traffic Analyzer Active       ║')))
        print(bold(cyan('╚══════════════════════════════════════════════════╝')))
        print(f"\n  {green('Monitoring:')} {', '.join(self.interfaces)}")
        print(f"  {green('Log dir:')} {self.log_dir}")
        print(f"  {yellow('Press Ctrl+C to stop and generate report')}\n")

        for iface in self.interfaces:
            if os.path.exists(f"/sys/class/net/{iface}"):
                t = threading.Thread(target=self.start_capture, args=(iface,), daemon=True)
                self.capture_threads.append(t)
                t.start()
            else:
                self.logger.warning(f"Interface {iface} not found — skipping")

        stats_thread = threading.Thread(target=self.print_live_stats, daemon=True)
        stats_thread.start()

        if not SCAPY_AVAILABLE:
            print(yellow("⚠️  Running in simulation mode (Scapy not available)"))
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            try:
                for t in self.capture_threads:
                    t.join()
            except KeyboardInterrupt:
                pass

        self.generate_final_report()

# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Secure Two-LAN Network Traffic Analyzer",
        epilog="Examples:\n  sudo python3 traffic-analyzer.py\n  sudo python3 traffic-analyzer.py -i eth0.10 eth0.20"
    )
    parser.add_argument("--interface", "-i", nargs="+",
                        default=DEFAULT_CONFIG["interfaces"])
    parser.add_argument("--log-dir", "-l", default=DEFAULT_CONFIG["log_dir"])
    parser.add_argument("--daemon", "-d", action="store_true")
    parser.add_argument("--stats-interval", "-s", type=int,
                        default=DEFAULT_CONFIG["stats_interval"])
    return parser.parse_args()

def main():
    args = parse_args()
    if os.geteuid() != 0:
        print(red("❌ Requires root: sudo python3 traffic-analyzer.py"))
        sys.exit(1)
    DEFAULT_CONFIG["stats_interval"] = args.stats_interval
    analyzer = TrafficAnalyzer(
        interfaces=args.interface,
        log_dir=args.log_dir,
        daemon_mode=args.daemon
    )
    analyzer.run()

if __name__ == "__main__":
    main()
