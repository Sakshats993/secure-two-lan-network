#!/usr/bin/env python3
"""
=============================================================================
Security Report Generator
=============================================================================
Aggregates security data from:
  - Traffic analyzer logs (JSON alerts)
  - DHCP monitor alerts
  - iptables firewall logs (syslog)
  - System auth logs
=============================================================================
"""

import os
import re
import sys
import json
import glob
import gzip
import argparse
import datetime
from typing import Dict, List
from collections import Counter

REPORT_DIR = "/var/log/security-reports"
TRAFFIC_LOG_DIR = "/var/log/traffic"
ALERT_LOG = "/var/log/security-events/traffic-alerts.log"
DHCP_ALERT_LOG = "/var/log/dhcp-monitor/alerts.log"
SYSLOG = "/var/log/syslog"
AUTH_LOG = "/var/log/auth.log"

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


class SecurityReportGenerator:
    """
    Aggregates security data from multiple log sources and generates
    formatted reports in console and JSON formats.
    """

    def __init__(self, quick_mode: bool = False):
        self.quick_mode = quick_mode
        self.report_time = datetime.datetime.now()
        self.report_data = {
            "metadata": {
                "generated_at": self.report_time.isoformat(),
                "type": "quick" if quick_mode else "full",
                "hostname": os.uname().nodename
            },
            "traffic_alerts": [],
            "dhcp_alerts": [],
            "firewall_events": [],
            "auth_events": {},
            "capture_files": {},
            "summary": {}
        }

    def load_json_alerts(self, filepath: str) -> List[Dict]:
        alerts = []
        if not os.path.exists(filepath):
            return alerts
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except PermissionError:
            pass
        return alerts

    def analyze_firewall_logs(self) -> List[Dict]:
        events = []
        ipt_pattern = re.compile(
            r'(\w+\s+\d+\s+[\d:]+).*'
            r'(IPT-[\w-]+).*'
            r'SRC=([\d.]+).*'
            r'DST=([\d.]+).*'
            r'PROTO=(\w+)'
        )
        for log_file in [SYSLOG] + glob.glob(f"{SYSLOG}.*.gz")[:1]:
            try:
                opener = gzip.open if log_file.endswith('.gz') else open
                mode = 'rt' if log_file.endswith('.gz') else 'r'
                with opener(log_file, mode) as f:
                    for line in f:
                        if "IPT-" not in line:
                            continue
                        match = ipt_pattern.search(line)
                        if match:
                            events.append({
                                "timestamp": match.group(1),
                                "action": match.group(2),
                                "src_ip": match.group(3),
                                "dst_ip": match.group(4),
                                "protocol": match.group(5)
                            })
                        if self.quick_mode and len(events) > 100:
                            break
            except (PermissionError, Exception):
                continue
        return events

    def analyze_auth_logs(self) -> Dict:
        result = {
            "failed_ssh_attempts": 0,
            "successful_logins": 0,
            "top_failed_ips": [],
            "sudo_usage": 0
        }
        if not os.path.exists(AUTH_LOG):
            return result
        failed_ips: Counter = Counter()
        try:
            with open(AUTH_LOG, 'r') as f:
                for line in f:
                    if "Failed password" in line:
                        result["failed_ssh_attempts"] += 1
                        m = re.search(r'from ([\d.]+)', line)
                        if m:
                            failed_ips[m.group(1)] += 1
                    elif "Accepted" in line:
                        result["successful_logins"] += 1
                    elif "sudo:" in line:
                        result["sudo_usage"] += 1
        except PermissionError:
            pass
        result["top_failed_ips"] = [
            {"ip": ip, "count": c} for ip, c in failed_ips.most_common(10)
        ]
        return result

    def count_capture_files(self) -> Dict:
        result = {"total_files": 0, "total_size_mb": 0.0, "files": []}
        pcap_files = glob.glob(os.path.join(TRAFFIC_LOG_DIR, "*.pcap"))
        result["total_files"] = len(pcap_files)
        for f in pcap_files:
            try:
                size = os.path.getsize(f)
                result["total_size_mb"] += size / (1024 * 1024)
                result["files"].append({
                    "name": os.path.basename(f),
                    "size_kb": round(size / 1024, 1),
                    "modified": datetime.datetime.fromtimestamp(
                        os.path.getmtime(f)).isoformat()
                })
            except OSError:
                continue
        return result

    def generate_summary(self) -> Dict:
        traffic = self.report_data["traffic_alerts"]
        dhcp = self.report_data["dhcp_alerts"]
        fw = self.report_data["firewall_events"]

        high_alerts = sum(1 for a in traffic + dhcp if a.get("severity") == "HIGH")
        blocked = sum(1 for e in fw if "DROP" in e.get("action", "") or "BLOCK" in e.get("action", ""))

        event_types: Counter = Counter()
        for a in traffic + dhcp:
            event_types[a.get("event_type", "UNKNOWN")] += 1

        return {
            "total_alerts": len(traffic) + len(dhcp),
            "high_severity": high_alerts,
            "firewall_blocks": blocked,
            "top_event_types": dict(event_types.most_common(5)),
            "risk_level": "HIGH" if high_alerts > 5 else "MEDIUM" if high_alerts > 0 else "LOW"
        }

    def generate(self):
        print(cyan("📊 Generating security report..."))
        self.report_data["traffic_alerts"] = self.load_json_alerts(ALERT_LOG)
        self.report_data["dhcp_alerts"] = self.load_json_alerts(DHCP_ALERT_LOG)
        if not self.quick_mode:
            self.report_data["firewall_events"] = self.analyze_firewall_logs()
        self.report_data["auth_events"] = self.analyze_auth_logs()
        self.report_data["capture_files"] = self.count_capture_files()
        self.report_data["summary"] = self.generate_summary()
        self._print_report()
        self._save_report()

    def _print_report(self):
        r = self.report_data
        s = r["summary"]
        risk = s.get("risk_level", "UNKNOWN")
        risk_display = {"HIGH": red("🔴 HIGH"), "MEDIUM": yellow("🟡 MEDIUM"), "LOW": green("🟢 LOW")}.get(risk, risk)

        print(f"\n{bold(cyan('═' * 65))}")
        print(bold(cyan('  🔒 SECURE TWO-LAN NETWORK — SECURITY REPORT')))
        print(bold(cyan(f'  Generated: {self.report_time.strftime("%Y-%m-%d %H:%M:%S")}')))
        print(bold(cyan('═' * 65)))
        print(f"\n  {bold('Risk Level:')} {risk_display}")
        print(f"  {bold('Summary:')}")
        print(f"    • Total Alerts:    {s.get('total_alerts', 0)}")
        print(f"    • High Severity:   {red(str(s.get('high_severity', 0)))}")
        print(f"    • Firewall Blocks: {s.get('firewall_blocks', 0)}")

        traffic = r["traffic_alerts"]
        if traffic:
            print(f"\n  {bold(red('Traffic Alerts:'))} ({len(traffic)} total)")
            for a in traffic[-5:]:
                sev = a.get('severity', '?')
                fn = red if sev == "HIGH" else yellow
                print(f"    [{fn(sev)}] {a.get('event_type','?')}: {a.get('src_ip','?')} → {a.get('dst_ip','?')}")

        dhcp = r["dhcp_alerts"]
        if dhcp:
            print(f"\n  {bold(yellow('DHCP Alerts:'))} ({len(dhcp)} total)")
            for a in dhcp[-3:]:
                print(f"    [{a.get('severity','?')}] {a.get('alert_type','?')}: {a.get('details','?')}")

        auth = r.get("auth_events", {})
        if auth:
            print(f"\n  {bold('Auth Events:')}")
            print(f"    • Failed SSH: {auth.get('failed_ssh_attempts', 0)}")
            print(f"    • Successful: {auth.get('successful_logins', 0)}")
            print(f"    • Sudo: {auth.get('sudo_usage', 0)}")
            for e in auth.get("top_failed_ips", [])[:3]:
                print(f"      - {e['ip']}: {e['count']} attempts")

        caps = r.get("capture_files", {})
        if caps.get("total_files"):
            print(f"\n  {bold('Captures:')} {caps['total_files']} files | {caps.get('total_size_mb', 0):.2f} MB")

        top = s.get("top_event_types", {})
        if top:
            print(f"\n  {bold('Top Event Types:')}")
            for k, v in top.items():
                print(f"    • {k}: {v}")

        print(f"\n{bold(cyan('═' * 65))}")

    def _save_report(self):
        os.makedirs(REPORT_DIR, exist_ok=True)
        report_file = os.path.join(
            REPORT_DIR,
            f"security_report_{self.report_time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(report_file, 'w') as f:
                json.dump(self.report_data, f, indent=2, default=str)
            print(f"\n{green(f'✅ Report saved: {report_file}')}")
        except Exception as e:
            print(f"{red(f'Failed to save: {e}')}")


def main():
    parser = argparse.ArgumentParser(description="Security Report Generator")
    parser.add_argument("--quick", action="store_true", help="Quick report (skip heavy analysis)")
    parser.add_argument("--full", action="store_true", help="Full comprehensive report")
    args = parser.parse_args()
    SecurityReportGenerator(quick_mode=args.quick and not args.full).generate()

if __name__ == "__main__":
    main()
