# 🏗️ Network Architecture Documentation

## Overview

The Secure Two-LAN Network implements a layered security architecture with strict zone separation between internal (LAN1) and DMZ (LAN2) networks using VLAN segmentation on a single physical interface.

## Network Topology

```
┌──────────────────────────────────────────────────────────────────┐
│                        HOST SYSTEM                               │
│                                                                  │
│  ┌─────────────┐  VLAN 10   ┌──────────────────────────────┐   │
│  │   eth0.10   │────────────│  LAN1 - Internal (Trusted)   │   │
│  │192.168.1.1  │            │  192.168.1.0/24              │   │
│  └─────────────┘            │  DHCP: .100-.200             │   │
│                             └──────────────────────────────┘   │
│  ┌──────────┐                         │                         │
│  │   eth0   │  BASE INTERFACE         │ HTTP/HTTPS only         │
│  │ (uplink) │                         ▼                         │
│  └──────────┘            ┌─────────────────────┐               │
│                           │   Web Server        │               │
│  ┌─────────────┐  VLAN 20 │   192.168.1.10      │               │
│  │   eth0.20   │──────────└─────────────────────┘               │
│  │192.168.2.1  │            ╳ BLOCKED ╳                         │
│  └─────────────┘                                                 │
│                             ┌──────────────────────────────┐   │
│                             │  LAN2 - DMZ (External)        │   │
│                             │  192.168.2.0/24               │   │
│                             │  DHCP: .100-.200              │   │
│                             └──────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Traffic Flow Matrix

| Source      | Destination  | Protocol    | Action   | Rule                 |
|-------------|--------------|-------------|----------|----------------------|
| LAN1        | Web Server   | TCP 80/443  | ✅ ALLOW | FORWARD chain        |
| LAN1        | Internet     | Any         | ✅ ALLOW | NAT Masquerade       |
| LAN1        | LAN2         | Any         | 🚫 BLOCK | FORWARD DROP         |
| LAN2        | LAN1         | Any         | 🚫 BLOCK | FORWARD DROP         |
| LAN2        | Internet     | TCP 80/443  | ✅ ALLOW | FORWARD → NAT        |
| Any         | DHCP Server  | UDP 67/68   | ✅ ALLOW | INPUT chain          |
| Rogue DHCP  | Broadcast    | UDP 67      | 🚫 BLOCK | DHCP_SNOOP chain     |

## VLAN Configuration

| VLAN ID | Interface | Network          | Purpose           |
|---------|-----------|------------------|-------------------|
| 10      | eth0.10   | 192.168.1.0/24   | Internal LAN      |
| 20      | eth0.20   | 192.168.2.0/24   | DMZ/External LAN  |

## IP Address Plan

| Role           | IP Address       | Notes                    |
|----------------|------------------|--------------------------|
| LAN1 Gateway   | 192.168.1.1      | eth0.10 — VLAN 10        |
| LAN2 Gateway   | 192.168.2.1      | eth0.20 — VLAN 20        |
| Web Server     | 192.168.1.10     | Static or DHCP reserved  |
| LAN1 DHCP Pool | .100 → .200      | 101 addresses available  |
| LAN2 DHCP Pool | .100 → .200      | 101 addresses available  |

## Security Layers

```
Layer 7 │ Application │ Apache ACLs, ModSecurity, Security Headers
Layer 4 │ Transport   │ iptables port filtering, SYN flood protection
Layer 3 │ Network     │ IP-based ACLs, anti-spoofing, NAT
Layer 2 │ Data Link   │ DHCP Snooping, VLAN segmentation
Layer 1 │ Physical    │ Interface promiscuous mode control
```

## Monitoring Stack

```
Traffic Capture (tcpdump) ──► .pcap files ──► Wireshark analysis
       │
       ▼
Traffic Analyzer (Scapy) ──► Security events (JSON) ──► Security Report
       │
       ▼
DHCP Monitor ──► Lease alerts ──► Alert log
       │
       ▼
Security Report Generator ──► /var/log/security-reports/
```
