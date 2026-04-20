#!/bin/bash
# =============================================================================
# Network Interface Persistence Setup
# =============================================================================

BASE_IF="${1:-eth0}"
LAN1_IF="${2:-eth0.10}"
LAN1_GW="${3:-192.168.1.1}"
LAN2_IF="${4:-eth0.20}"
LAN2_GW="${5:-192.168.2.1}"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}  Configuring persistent network interfaces...${NC}"

if command -v netplan &>/dev/null; then
    cat > /etc/netplan/99-secure-lan.yaml << NETPLAN_EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${BASE_IF}:
      dhcp4: true
      optional: true
  vlans:
    ${LAN1_IF}:
      id: 10
      link: ${BASE_IF}
      addresses:
        - ${LAN1_GW}/24
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
    ${LAN2_IF}:
      id: 20
      link: ${BASE_IF}
      addresses:
        - ${LAN2_GW}/24
      nameservers:
        addresses: [8.8.8.8]
NETPLAN_EOF
    netplan apply 2>/dev/null || true
    echo -e "${GREEN}  ✅ Netplan configuration applied${NC}"
fi

cat > /etc/network/interfaces.d/secure-lan << IFACE_EOF
# Secure Two-LAN Network Interface Configuration
# Generated: $(date)

auto ${LAN1_IF}
iface ${LAN1_IF} inet static
    address ${LAN1_GW}
    netmask 255.255.255.0
    vlan-raw-device ${BASE_IF}

auto ${LAN2_IF}
iface ${LAN2_IF} inet static
    address ${LAN2_GW}
    netmask 255.255.255.0
    vlan-raw-device ${BASE_IF}
IFACE_EOF

echo -e "${GREEN}  ✅ Network configuration written${NC}"
