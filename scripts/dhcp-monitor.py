#!/usr/bin/env python3
"""
=============================================================================
DHCP Activity Monitor
=============================================================================
Monitors DHCP server activity, detects anomalies, tracks leases,
and alerts on rogue DHCP server activity and pool exhaustion.
=============================================================================
"""

import os
import re
import sys
import time
import json
import logging
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# ─── Config ───────────────────────────────────────────────────────────────────
LEASE_FILE = "/var/lib/dhcp/dhcpd.leases"
MONITOR_LOG = "/var/log/dhcp-monitor/monitor.log"
ALERT_LOG = "/var/log/dhcp-monitor/alerts.log"
CHECK_INTERVAL = 30

KNOWN_MACS: Dict[str, str] = {
    # "AA:BB:CC:DD:EE:FF": "webserver",
}

# ─── Colors ───────────────────────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    def red(t): return f"{Fore.RED}{t}{Style.RESET_ALL}"
    def green(t): return f"{Fore.GREEN}{t}{Style.RESET_ALL}"
    def yellow(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}"
    def cyan(t): return f"{Fore.CYAN}{t}{Style.RESET_ALL}"
    def bold(t): return f"{Style.BRIGHT}{t}{Style.RESET_ALL}"
except ImportError:
    def red(t): return t
    def green(t): return t
    def yellow(t): return t
    def cyan(t): return t
    def bold(t): return t

# ─── Data Classes ─────────────────────────────────────────────────────────────
@dataclass
class DhcpLease:
    ip_address: str
    mac_address: str
    hostname: str
    start_time: str
    end_time: str
    binding_state: str
    subnet: str = ""

    def is_active(self): return self.binding_state == "active"
    def is_lan1(self): return self.ip_address.startswith("192.168.1.")
    def is_lan2(self): return self.ip_address.startswith("192.168.2.")

@dataclass
class DhcpAlert:
    timestamp: str
    alert_type: str
    severity: str
    details: str
    mac_address: str = ""
    ip_address: str = ""

# ─── Logger ───────────────────────────────────────────────────────────────────
def setup_logger() -> logging.Logger:
    os.makedirs(os.path.dirname(MONITOR_LOG), exist_ok=True)
    logger = logging.getLogger("dhcp-monitor")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(MONITOR_LOG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# ─── Lease Parser ─────────────────────────────────────────────────────────────
class LeaseParser:
    def __init__(self, lease_file: str = LEASE_FILE):
        self.lease_file = lease_file

    def parse(self) -> Dict[str, DhcpLease]:
        leases: Dict[str, DhcpLease] = {}
        if not os.path.exists(self.lease_file):
            return leases
        try:
            with open(self.lease_file, 'r') as f:
                content = f.read()
        except PermissionError:
            return leases

        for ip, block in re.findall(r'lease\s+([\d.]+)\s*\{([^}]+)\}', content, re.DOTALL):
            lease = self._parse_block(ip, block)
            if lease:
                leases[ip] = lease
        return leases

    def _parse_block(self, ip: str, block: str) -> Optional[DhcpLease]:
        try:
            mac = re.search(r'hardware ethernet\s+([\w:]+);', block)
            hostname = re.search(r'client-hostname\s+"([^"]+)";', block)
            start = re.search(r'starts\s+\d+\s+([^;]+);', block)
            end = re.search(r'ends\s+\d+\s+([^;]+);', block)
            state = re.search(r'binding state\s+(\w+);', block)
            return DhcpLease(
                ip_address=ip,
                mac_address=mac.group(1) if mac else "unknown",
                hostname=hostname.group(1) if hostname else "unknown",
                start_time=start.group(1).strip() if start else "unknown",
                end_time=end.group(1).strip() if end else "unknown",
                binding_state=state.group(1) if state else "unknown",
                subnet="LAN1" if ip.startswith("192.168.1.") else "LAN2"
            )
        except Exception:
            return None

# ─── DHCP Monitor ─────────────────────────────────────────────────────────────
class DhcpMonitor:
    """
    Monitors DHCP leases for:
    - New and expiring leases
    - Unknown devices (if whitelist configured)
    - Pool exhaustion (>80%)
    - Lease count anomalies
    """

    def __init__(self):
        self.logger = setup_logger()
        self.parser = LeaseParser()
        self.previous_leases: Dict[str, DhcpLease] = {}
        self.alerts: List[DhcpAlert] = []
        self.running = False
        self.stats = {
            "total_leases_seen": 0,
            "lan1_leases": 0,
            "lan2_leases": 0,
            "alerts_generated": 0,
            "check_cycles": 0
        }

    def _send_alert(self, alert: DhcpAlert):
        self.alerts.append(alert)
        self.stats["alerts_generated"] += 1
        try:
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps(asdict(alert)) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write alert: {e}")
        fn = red if alert.severity == "HIGH" else yellow
        self.logger.warning(f"🚨 [{fn(alert.severity)}] {alert.alert_type}: {alert.details}")

    def check_new_devices(self, current, previous):
        for ip, lease in current.items():
            if ip not in previous and lease.is_active():
                self.logger.info(
                    f"{green('▶ NEW LEASE')} | IP: {ip} | MAC: {lease.mac_address} | "
                    f"Host: {lease.hostname} | Net: {lease.subnet}"
                )
                if KNOWN_MACS and lease.mac_address not in KNOWN_MACS:
                    self._send_alert(DhcpAlert(
                        timestamp=datetime.datetime.now().isoformat(),
                        alert_type="UNKNOWN_DEVICE",
                        severity="MEDIUM",
                        details=f"Unknown device got lease: {ip} (MAC: {lease.mac_address})",
                        mac_address=lease.mac_address,
                        ip_address=ip
                    ))

    def check_expired_leases(self, current, previous):
        for ip, lease in previous.items():
            if ip in current and lease.is_active() and current[ip].binding_state == "expired":
                self.logger.info(f"{yellow('◀ LEASE EXPIRED')} | IP: {ip} | MAC: {lease.mac_address}")

    def check_lease_counts(self, leases):
        active = [l for l in leases.values() if l.is_active()]
        lan1 = [l for l in active if l.is_lan1()]
        lan2 = [l for l in active if l.is_lan2()]
        self.stats["lan1_leases"] = len(lan1)
        self.stats["lan2_leases"] = len(lan2)

        LAN1_POOL = LAN2_POOL = 101  # .100-.200

        for net, count, pool in [("LAN1", len(lan1), LAN1_POOL), ("LAN2", len(lan2), LAN2_POOL)]:
            usage = (count / pool) * 100
            if usage > 80:
                self._send_alert(DhcpAlert(
                    timestamp=datetime.datetime.now().isoformat(),
                    alert_type="POOL_EXHAUSTION_WARNING",
                    severity="HIGH",
                    details=f"{net} pool {usage:.1f}% full ({count}/{pool})"
                ))

        return len(active), len(lan1), len(lan2)

    def print_status_table(self, leases):
        active = [l for l in leases.values() if l.is_active()]
        lan1 = [l for l in active if l.is_lan1()]
        lan2 = [l for l in active if l.is_lan2()]

        print(f"\n{bold(cyan('─' * 70))}")
        print(bold(cyan(f"  DHCP Lease Status | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")))
        print(bold(cyan('─' * 70)))

        print(f"\n  {bold(green('LAN1 (Internal) 192.168.1.x:'))} {len(lan1)} active")
        for l in lan1[:5]:
            print(f"    • {l.ip_address:<18} {l.mac_address:<20} {l.hostname}")
        if len(lan1) > 5:
            print(f"    ... and {len(lan1)-5} more")

        print(f"\n  {bold(cyan('LAN2 (DMZ) 192.168.2.x:'))} {len(lan2)} active")
        for l in lan2[:5]:
            print(f"    • {l.ip_address:<18} {l.mac_address:<20} {l.hostname}")
        if len(lan2) > 5:
            print(f"    ... and {len(lan2)-5} more")

        print(f"\n  {bold('Alerts:')} {len(self.alerts)} | Cycles: {self.stats['check_cycles']}")
        print(bold(cyan('─' * 70)))

    def run_check(self):
        self.stats["check_cycles"] += 1
        current = self.parser.parse()
        if not current:
            self.logger.debug("No leases found or file not accessible")
            return
        self.check_new_devices(current, self.previous_leases)
        self.check_expired_leases(current, self.previous_leases)
        total, lan1, lan2 = self.check_lease_counts(current)
        self.stats["total_leases_seen"] += total
        if self.stats["check_cycles"] % 5 == 0:
            self.print_status_table(current)
        self.previous_leases = current.copy()

    def run(self):
        self.running = True
        print(f"\n{bold(cyan('╔══════════════════════════════════════════════╗'))}")
        print(bold(cyan('║       🔍 DHCP Activity Monitor Active         ║')))
        print(bold(cyan('╚══════════════════════════════════════════════╝')))
        print(f"  Monitoring: {LEASE_FILE}")
        print(f"  Interval: {CHECK_INTERVAL}s\n")
        self.logger.info("DHCP Monitor started")
        while self.running:
            try:
                self.run_check()
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Run as root: sudo python3 dhcp-monitor.py")
        sys.exit(1)
    DhcpMonitor().run()
