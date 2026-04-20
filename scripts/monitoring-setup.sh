#!/bin/bash
# =============================================================================
# Monitoring Tools Setup
# =============================================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_DIR="/var/log/traffic"
MONITOR_LOG="/var/log/dhcp-monitor"

echo -e "${CYAN}  Setting up monitoring infrastructure...${NC}"

mkdir -p "$LOG_DIR" "$MONITOR_LOG" /var/log/security-events

cat > /etc/logrotate.d/secure-lan-traffic << 'ROTATE_EOF'
/var/log/traffic/*.pcap {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}

/var/log/dhcp-monitor/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}

/var/log/security-events/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
ROTATE_EOF

echo -e "${GREEN}  ✅ Log rotation configured${NC}"

ip link set eth0.10 promisc on 2>/dev/null || true
ip link set eth0.20 promisc on 2>/dev/null || true
echo -e "${GREEN}  ✅ Promiscuous mode enabled${NC}"

cat > /usr/local/bin/check-dhcp-leases << 'LEASE_EOF'
#!/bin/bash
LEASE_FILE="/var/lib/dhcp/dhcpd.leases"
ALERT_LOG="/var/log/dhcp-monitor/alerts.log"
mkdir -p "$(dirname "$ALERT_LOG")"
if [[ -f "$LEASE_FILE" ]]; then
    active_count=$(grep -c "binding state active" "$LEASE_FILE" 2>/dev/null || echo 0)
    echo "[$(date)] Active DHCP leases: $active_count" >> "$ALERT_LOG"
    if [[ $active_count -gt 50 ]]; then
        echo "[$(date)] WARNING: High lease count: $active_count" >> "$ALERT_LOG"
        logger -p local0.warning "DHCP Alert: High lease count $active_count"
    fi
fi
LEASE_EOF
chmod +x /usr/local/bin/check-dhcp-leases

(crontab -l 2>/dev/null; cat << 'CRON_EOF'
# Secure LAN Monitoring Jobs
*/5 * * * * /usr/local/bin/check-dhcp-leases
*/10 * * * * /usr/bin/python3 /opt/secure-lan/scripts/security-report.py --quick
0 */6 * * * /usr/bin/python3 /opt/secure-lan/scripts/security-report.py --full
0 2 * * * /usr/bin/find /var/log/traffic -name "*.pcap" -mtime +7 -delete
CRON_EOF
) | crontab - 2>/dev/null || true
echo -e "${GREEN}  ✅ Monitoring cron jobs scheduled${NC}"

mkdir -p /opt/secure-lan/scripts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cp -r "${SCRIPT_DIR}/scripts/"* /opt/secure-lan/scripts/ 2>/dev/null || true
echo -e "${GREEN}  ✅ Monitoring setup complete${NC}"
