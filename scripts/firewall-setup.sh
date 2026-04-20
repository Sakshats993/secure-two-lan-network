#!/bin/bash
# =============================================================================
# Firewall Rules Setup - iptables
# Implements zone-based traffic control between LAN1 and LAN2
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

LAN1_NET="192.168.1.0/24"
LAN2_NET="192.168.2.0/24"
WEB_SERVER="192.168.1.10"
LAN1_IF="eth0.10"
LAN2_IF="eth0.20"

echo -e "${CYAN}  Configuring iptables firewall rules...${NC}"

# Flush existing rules
iptables -F; iptables -X
iptables -t nat -F; iptables -t nat -X
iptables -t mangle -F; iptables -t mangle -X

# Default drop policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
echo -e "${CYAN}  Default DROP policies set${NC}"

# ─── INPUT Chain ──────────────────────────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p udp --dport 67 -j ACCEPT
iptables -A INPUT -p udp --dport 68 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -s "$LAN1_NET" -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s "$LAN1_NET" -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s "$LAN1_NET" -p icmp -j ACCEPT
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-INPUT-DROP: " --log-level 7
echo -e "${GREEN}  ✅ INPUT chain configured${NC}"

# ─── FORWARD Chain ────────────────────────────────────────────────────────────
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s "$LAN1_NET" -d "$WEB_SERVER" -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s "$LAN1_NET" -d "$WEB_SERVER" -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i "$LAN1_IF" -o eth0 -j ACCEPT
iptables -A FORWARD -i "$LAN2_IF" -o eth0 -p tcp -m multiport --dports 80,443 -j ACCEPT

# BLOCK: LAN2 → LAN1
iptables -A FORWARD -s "$LAN2_NET" -i "$LAN2_IF" -o "$LAN1_IF" \
    -j LOG --log-prefix "IPT-LAN2-TO-LAN1-BLOCKED: " --log-level 6
iptables -A FORWARD -s "$LAN2_NET" -i "$LAN2_IF" -o "$LAN1_IF" -j DROP

# BLOCK: LAN1 → LAN2
iptables -A FORWARD -s "$LAN1_NET" -i "$LAN1_IF" -o "$LAN2_IF" \
    -j LOG --log-prefix "IPT-LAN1-TO-LAN2-BLOCKED: " --log-level 6
iptables -A FORWARD -s "$LAN1_NET" -i "$LAN1_IF" -o "$LAN2_IF" -j DROP

iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "IPT-FORWARD-DROP: " --log-level 7
echo -e "${GREEN}  ✅ FORWARD chain configured${NC}"

# ─── NAT ──────────────────────────────────────────────────────────────────────
iptables -t nat -A POSTROUTING -s "$LAN1_NET" -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s "$LAN2_NET" -o eth0 -j MASQUERADE
echo -e "${GREEN}  ✅ NAT/Masquerade configured${NC}"

# ─── Anti-Spoofing ────────────────────────────────────────────────────────────
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
echo -e "${GREEN}  ✅ Anti-spoofing rules applied${NC}"

# ─── Port Scan Protection ─────────────────────────────────────────────────────
iptables -N PORT_SCAN 2>/dev/null || true
iptables -A PORT_SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
    -m limit --limit 1/s -j RETURN
iptables -A PORT_SCAN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j PORT_SCAN
echo -e "${GREEN}  ✅ Port scan protection configured${NC}"

# ─── SYN Flood Protection ─────────────────────────────────────────────────────
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
echo -e "${GREEN}  ✅ SYN flood protection active${NC}"

# ─── DHCP Snooping ────────────────────────────────────────────────────────────
iptables -N DHCP_SNOOP 2>/dev/null || iptables -F DHCP_SNOOP
iptables -A DHCP_SNOOP -s 192.168.1.1 -j ACCEPT
iptables -A DHCP_SNOOP -s 192.168.2.1 -j ACCEPT
iptables -A DHCP_SNOOP -p udp --sport 67 \
    -m limit --limit 3/min -j LOG --log-prefix "ROGUE-DHCP-DETECTED: " --log-level 4
iptables -A DHCP_SNOOP -p udp --sport 67 -j DROP
iptables -I FORWARD 1 -p udp --sport 67 -j DHCP_SNOOP
echo -e "${GREEN}  ✅ DHCP snooping rules applied${NC}"

# ─── Save Rules ───────────────────────────────────────────────────────────────
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    echo -e "${GREEN}  ✅ Rules saved via netfilter-persistent${NC}"
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo -e "${GREEN}  ✅ Rules saved to /etc/iptables/rules.v4${NC}"
fi

echo -e "\n${CYAN}  Current FORWARD rules (summary):${NC}"
echo -e "${YELLOW}"
iptables -L FORWARD -n --line-numbers 2>/dev/null | head -20
echo -e "${NC}"
echo -e "${GREEN}  ✅ Firewall configuration complete${NC}"
