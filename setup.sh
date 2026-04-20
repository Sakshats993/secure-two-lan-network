#!/bin/bash
# =============================================================================
# Secure Two-LAN Network - Master Setup Script
# =============================================================================
# Author: Saksha
# Version: 1.0.0
# Description: Automates complete network security environment setup
# =============================================================================

set -euo pipefail

# ─── Color Codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ─── Configuration Variables ──────────────────────────────────────────────────
LAN1_NETWORK="192.168.1.0/24"
LAN1_GATEWAY="192.168.1.1"
LAN1_RANGE_START="192.168.1.100"
LAN1_RANGE_END="192.168.1.200"
LAN1_INTERFACE="eth0.10"

LAN2_NETWORK="192.168.2.0/24"
LAN2_GATEWAY="192.168.2.1"
LAN2_RANGE_START="192.168.2.100"
LAN2_RANGE_END="192.168.2.200"
LAN2_INTERFACE="eth0.20"

WEB_SERVER_IP="192.168.1.10"
BASE_INTERFACE="eth0"
LOG_DIR="/var/log/traffic"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_LOG="/var/log/secure-lan-setup.log"

# ─── Logging Functions ────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >> "$SETUP_LOG" 2>/dev/null || true
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       🔒 Secure Two-LAN Network Setup Script v1.0.0         ║"
    echo "║          Dual-LAN Segmentation + Security Hardening         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step()    { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n${WHITE}  ▶ STEP: $1${NC}\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; log "INFO" "Starting step: $1"; }
print_success() { echo -e "  ${GREEN}✅ $1${NC}"; log "SUCCESS" "$1"; }
print_warning() { echo -e "  ${YELLOW}⚠️  $1${NC}"; log "WARNING" "$1"; }
print_error()   { echo -e "  ${RED}❌ $1${NC}"; log "ERROR" "$1"; }
print_info()    { echo -e "  ${CYAN}ℹ️  $1${NC}"; log "INFO" "$1"; }

# ─── Utility Functions ────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -eq 0 ]] || { print_error "This script must be run as root (sudo)"; exit 1; }
}

check_os() {
    if ! grep -qiE "ubuntu|debian" /etc/os-release 2>/dev/null; then
        print_warning "This script is optimized for Ubuntu/Debian"
        read -rp "Continue anyway? (y/N): " choice
        [[ "$choice" =~ ^[Yy]$ ]] || exit 1
    fi
    print_success "OS compatibility check passed"
}

check_dependencies() {
    local deps=("ip" "iptables" "systemctl" "apt-get")
    local missing=()
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    [[ ${#missing[@]} -gt 0 ]] && { print_error "Missing: ${missing[*]}"; exit 1; }
    print_success "All core dependencies found"
}

create_log_dirs() {
    mkdir -p "$LOG_DIR" /var/log/dhcp-monitor
    chmod 755 "$LOG_DIR"
    touch "$SETUP_LOG"
    print_success "Log directories created at $LOG_DIR"
}

# ─── Step 1: System Update ────────────────────────────────────────────────────
update_system() {
    print_step "System Update & Package Installation"
    print_info "Updating package lists..."
    apt-get update -qq
    print_info "Installing required packages..."
    apt-get install -y -qq \
        isc-dhcp-server apache2 ufw iptables iptables-persistent \
        netfilter-persistent wireshark tcpdump nload iftop nmap \
        python3 python3-pip python3-scapy vlan net-tools curl wget \
        htop iputils-ping dnsutils openssl libapache2-mod-security2 \
        fail2ban auditd
    print_info "Installing Python packages..."
    pip3 install -q scapy psutil colorama tabulate schedule 2>/dev/null || \
        print_warning "Some Python packages may not have installed"
    print_success "System packages installed successfully"
}

# ─── Step 2: Network Interfaces ──────────────────────────────────────────────
setup_network_interfaces() {
    print_step "Network Interface Configuration"
    print_info "Loading 8021q VLAN kernel module..."
    modprobe 8021q
    grep -q "8021q" /etc/modules 2>/dev/null || echo "8021q" >> /etc/modules

    if ! ip link show "$BASE_INTERFACE" &>/dev/null; then
        BASE_INTERFACE=$(ip link show | grep -E "^[0-9]+: (enp|ens|eth)" | \
            head -1 | awk '{print $2}' | tr -d ':')
        print_warning "eth0 not found. Using: $BASE_INTERFACE"
        LAN1_INTERFACE="${BASE_INTERFACE}.10"
        LAN2_INTERFACE="${BASE_INTERFACE}.20"
    fi

    ip link delete "$LAN1_INTERFACE" 2>/dev/null || true
    ip link delete "$LAN2_INTERFACE" 2>/dev/null || true

    ip link add link "$BASE_INTERFACE" name "$LAN1_INTERFACE" type vlan id 10
    ip addr add "${LAN1_GATEWAY}/24" dev "$LAN1_INTERFACE"
    ip link set "$LAN1_INTERFACE" up
    print_success "LAN1 VLAN (eth0.10) created → $LAN1_GATEWAY/24"

    ip link add link "$BASE_INTERFACE" name "$LAN2_INTERFACE" type vlan id 20
    ip addr add "${LAN2_GATEWAY}/24" dev "$LAN2_INTERFACE"
    ip link set "$LAN2_INTERFACE" up
    print_success "LAN2 VLAN (eth0.20) created → $LAN2_GATEWAY/24"

    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    cat >> /etc/sysctl.conf << 'SYSCTL_EOF'

# Secure Two-LAN Network Security Settings
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.log_martians=1
SYSCTL_EOF

    sysctl -p > /dev/null 2>&1
    print_success "Kernel security parameters applied"
    bash "${SCRIPT_DIR}/scripts/network-setup.sh" "$BASE_INTERFACE" \
        "$LAN1_INTERFACE" "$LAN1_GATEWAY" "$LAN2_INTERFACE" "$LAN2_GATEWAY"
    print_success "Network interfaces configured successfully"
}

# ─── Step 3: DHCP Server ─────────────────────────────────────────────────────
setup_dhcp_server() {
    print_step "DHCP Server Configuration"
    print_info "Writing DHCP server configuration..."

    cat > /etc/dhcp/dhcpd.conf << DHCP_EOF
# =============================================================================
# ISC DHCP Server Configuration - Secure Two-LAN Network
# Generated: $(date)
# =============================================================================

default-lease-time 600;
max-lease-time 7200;
min-lease-time 300;
ddns-update-style none;
authoritative;
log-facility local7;
option domain-name "secure-lan.local";

subnet 192.168.1.0 netmask 255.255.255.0 {
  range ${LAN1_RANGE_START} ${LAN1_RANGE_END};
  option routers ${LAN1_GATEWAY};
  option subnet-mask 255.255.255.0;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
  option domain-name "internal.lan";
  option broadcast-address 192.168.1.255;
  default-lease-time 600;
  max-lease-time 7200;
}

subnet 192.168.2.0 netmask 255.255.255.0 {
  range ${LAN2_RANGE_START} ${LAN2_RANGE_END};
  option routers ${LAN2_GATEWAY};
  option subnet-mask 255.255.255.0;
  option domain-name-servers 8.8.8.8;
  option domain-name "dmz.lan";
  option broadcast-address 192.168.2.255;
  default-lease-time 300;
  max-lease-time 3600;
}

# Static Reservation Example:
# host webserver {
#     hardware ethernet AA:BB:CC:DD:EE:FF;
#     fixed-address ${WEB_SERVER_IP};
# }
DHCP_EOF

    cat > /etc/default/isc-dhcp-server << IFACE_EOF
INTERFACESv4="${LAN1_INTERFACE} ${LAN2_INTERFACE}"
INTERFACESv6=""
IFACE_EOF

    systemctl enable isc-dhcp-server
    systemctl restart isc-dhcp-server
    systemctl is-active --quiet isc-dhcp-server && \
        print_success "DHCP server running" || \
        print_warning "DHCP server may not have started. Check journalctl -u isc-dhcp-server"
}

# ─── Step 4: Web Server ───────────────────────────────────────────────────────
setup_web_server() {
    print_step "Web Server Configuration (Apache2)"
    a2enmod ssl headers rewrite security2 2>/dev/null || true

    cp -r "${SCRIPT_DIR}/web/"* /var/www/html/ 2>/dev/null || true

    cat > /etc/apache2/sites-available/000-default.conf << 'APACHE_EOF'
<VirtualHost *:80>
    ServerAdmin admin@secure-lan.local
    DocumentRoot /var/www/html
    ServerName 192.168.1.10
    ServerTokens Prod
    ServerSignature Off

    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'"

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require ip 192.168.1.0/24
        Require ip 127.0.0.1
    </Directory>

    ErrorLog /var/log/apache2/error.log
    CustomLog /var/log/apache2/access.log combined
</VirtualHost>
APACHE_EOF

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow from 192.168.1.0/24 to any port 80 proto tcp comment "LAN1 HTTP"
    ufw allow from 192.168.1.0/24 to any port 443 proto tcp comment "LAN1 HTTPS"
    ufw allow 22/tcp comment "SSH Management"
    ufw --force enable

    systemctl enable apache2
    systemctl restart apache2
    systemctl is-active --quiet apache2 && \
        print_success "Apache2 running — restricted to LAN1" || \
        print_error "Apache2 failed to start"
}

# ─── Step 5: Firewall ─────────────────────────────────────────────────────────
setup_firewall() {
    print_step "Firewall Rules (iptables)"
    bash "${SCRIPT_DIR}/scripts/firewall-setup.sh"
    print_success "Firewall rules applied and saved"
}

# ─── Step 6: Security Hardening ──────────────────────────────────────────────
apply_security_hardening() {
    print_step "Security Hardening"
    bash "${SCRIPT_DIR}/scripts/security-hardening.sh"
    print_success "Security hardening complete"
}

# ─── Step 7: Monitoring ───────────────────────────────────────────────────────
setup_monitoring() {
    print_step "Traffic Monitoring Setup"
    mkdir -p "$LOG_DIR" /var/log/dhcp-monitor
    bash "${SCRIPT_DIR}/scripts/monitoring-setup.sh"
    print_success "Monitoring tools configured"
}

# ─── Step 8: Systemd Services ─────────────────────────────────────────────────
create_systemd_services() {
    print_step "Creating Systemd Service Units"

    cat > /etc/systemd/system/lan-traffic-capture.service << SERVICE_EOF
[Unit]
Description=LAN Traffic Capture Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash ${SCRIPT_DIR}/start-monitoring.sh
ExecStop=/bin/bash ${SCRIPT_DIR}/stop-monitoring.sh
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    cat > /etc/systemd/system/dhcp-monitor.service << SERVICE_EOF
[Unit]
Description=DHCP Activity Monitor
After=isc-dhcp-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/scripts/dhcp-monitor.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload
    systemctl enable lan-traffic-capture.service 2>/dev/null || true
    systemctl enable dhcp-monitor.service 2>/dev/null || true
    print_success "Systemd services created"
}

# ─── Final Summary ────────────────────────────────────────────────────────────
print_summary() {
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              ✅ SETUP COMPLETED SUCCESSFULLY                 ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-60s║\n" "  LAN1 (Internal): 192.168.1.0/24 → eth0.10"
    printf "║  %-60s║\n" "  LAN2 (DMZ):      192.168.2.0/24 → eth0.20"
    printf "║  %-60s║\n" "  Web Server:      192.168.1.10:80"
    printf "║  %-60s║\n" "  DHCP:  $(systemctl is-active isc-dhcp-server 2>/dev/null)"
    printf "║  %-60s║\n" "  Apache: $(systemctl is-active apache2 2>/dev/null)"
    printf "║  %-60s║\n" "  UFW: $(ufw status | head -1)"
    printf "║  %-60s║\n" "  Quick: sudo ./start-monitoring.sh"
    printf "║  %-60s║\n" "  Test:  sudo ./scripts/test-suite.sh"
    printf "║  %-60s║\n" "  Log: $SETUP_LOG"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    print_banner
    check_root; check_os; check_dependencies; create_log_dirs
    echo -e "\n  Starting setup at $(date)\n"
    update_system
    setup_network_interfaces
    setup_dhcp_server
    setup_web_server
    setup_firewall
    apply_security_hardening
    setup_monitoring
    create_systemd_services
    print_summary
}

main "$@"
