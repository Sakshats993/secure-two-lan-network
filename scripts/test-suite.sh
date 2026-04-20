#!/bin/bash
# =============================================================================
# Comprehensive Test Suite - Secure Two-LAN Network
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0; FAIL=0; WARN=0
LAN1_IF="eth0.10"
LAN2_IF="eth0.20"
WEB_SERVER="192.168.1.10"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ─── Helpers ──────────────────────────────────────────────────────────────────
assert_pass() {
    local name="$1" result="$2"
    if [[ "$result" == "0" ]]; then
        echo -e "  ${GREEN}✅ PASS${NC}: $name"; ((PASS++))
    else
        echo -e "  ${RED}❌ FAIL${NC}: $name"; ((FAIL++))
    fi
}

assert_contains() {
    local name="$1" output="$2" expected="$3"
    if echo "$output" | grep -q "$expected"; then
        echo -e "  ${GREEN}✅ PASS${NC}: $name"; ((PASS++))
    else
        echo -e "  ${RED}❌ FAIL${NC}: $name (expected: '$expected')"; ((FAIL++))
    fi
}

warn_test() { echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"; ((WARN++)); }

section() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  🧪 $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ─── Tests ────────────────────────────────────────────────────────────────────
test_network_interfaces() {
    section "Network Interface Tests"
    lsmod | grep -q 8021q; assert_pass "8021q VLAN module loaded" "$?"
    ip link show "$LAN1_IF" &>/dev/null; assert_pass "LAN1 ($LAN1_IF) exists" "$?"
    ip link show "$LAN2_IF" &>/dev/null; assert_pass "LAN2 ($LAN2_IF) exists" "$?"

    local lan1_ip; lan1_ip=$(ip addr show "$LAN1_IF" 2>/dev/null | grep -oP '192\.168\.1\.\d+' | head -1)
    [[ "$lan1_ip" == "192.168.1.1" ]]; assert_pass "LAN1 gateway IP ($lan1_ip)" "$?"

    local lan2_ip; lan2_ip=$(ip addr show "$LAN2_IF" 2>/dev/null | grep -oP '192\.168\.2\.\d+' | head -1)
    [[ "$lan2_ip" == "192.168.2.1" ]]; assert_pass "LAN2 gateway IP ($lan2_ip)" "$?"

    [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; assert_pass "IP forwarding enabled" "$?"
}

test_dhcp_server() {
    section "DHCP Server Tests"
    systemctl is-active --quiet isc-dhcp-server; assert_pass "DHCP service running" "$?"
    systemctl is-enabled --quiet isc-dhcp-server; assert_pass "DHCP enabled at boot" "$?"
    [[ -f /etc/dhcp/dhcpd.conf ]]; assert_pass "dhcpd.conf exists" "$?"
    assert_contains "LAN1 subnet in config" "$(cat /etc/dhcp/dhcpd.conf 2>/dev/null)" "192.168.1.0"
    assert_contains "LAN2 subnet in config" "$(cat /etc/dhcp/dhcpd.conf 2>/dev/null)" "192.168.2.0"
    ss -ulnp | grep -q ":67"; assert_pass "DHCP port 67 listening" "$?"
}

test_web_server() {
    section "Web Server Tests"
    systemctl is-active --quiet apache2; assert_pass "Apache2 running" "$?"
    systemctl is-enabled --quiet apache2; assert_pass "Apache2 enabled at boot" "$?"
    ss -tlnp | grep -q ":80"; assert_pass "Port 80 listening" "$?"
    [[ -f /var/www/html/index.html ]]; assert_pass "index.html exists" "$?"

    local code; code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
    [[ "$code" == "200" ]]; assert_pass "Web server returns HTTP 200" "$?"

    local hdrs; hdrs=$(curl -sI http://localhost/ 2>/dev/null)
    assert_contains "X-Frame-Options header" "$hdrs" "X-Frame-Options"
    assert_contains "X-Content-Type-Options header" "$hdrs" "X-Content-Type-Options"
}

test_firewall() {
    section "Firewall Tests"
    local rule_count; rule_count=$(iptables -L -n 2>/dev/null | wc -l)
    [[ $rule_count -gt 5 ]]; assert_pass "iptables rules loaded ($rule_count lines)" "$?"

    local input_pol; input_pol=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -o "DROP")
    [[ "$input_pol" == "DROP" ]]; assert_pass "INPUT default policy is DROP" "$?"

    local fwd_pol; fwd_pol=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -o "DROP")
    [[ "$fwd_pol" == "DROP" ]]; assert_pass "FORWARD default policy is DROP" "$?"

    ufw status 2>/dev/null | grep -q "Status: active"; assert_pass "UFW active" "$?"
    iptables -L FORWARD -n 2>/dev/null | grep -q "DROP"; assert_pass "FORWARD DROP rules exist" "$?"

    local lan2_block; lan2_block=$(iptables -L FORWARD -n 2>/dev/null | grep "192.168.2" | grep -c "DROP" || echo "0")
    [[ "$lan2_block" -gt 0 ]]; assert_pass "LAN2→LAN1 blocked" "$?"
    iptables -L INPUT -n 2>/dev/null | grep -q "10.0.0.0"; assert_pass "Anti-spoofing rules present" "$?"
}

test_security_services() {
    section "Security Services Tests"
    systemctl is-active --quiet fail2ban && assert_pass "Fail2Ban running" "0" || warn_test "Fail2Ban not running"
    [[ -d /var/log/traffic ]]; assert_pass "Traffic log directory exists" "$?"
    [[ -f "${SCRIPT_DIR}/scripts/traffic-analyzer.py" ]]; assert_pass "traffic-analyzer.py exists" "$?"
    [[ -f "${SCRIPT_DIR}/scripts/dhcp-monitor.py" ]]; assert_pass "dhcp-monitor.py exists" "$?"
    python3 --version &>/dev/null; assert_pass "Python3 available" "$?"
    command -v tcpdump &>/dev/null; assert_pass "tcpdump installed" "$?"
    command -v tshark &>/dev/null || command -v wireshark &>/dev/null
    assert_pass "Wireshark/tshark available" "$?"
}

test_sysctl() {
    section "Kernel Security Parameters"
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]]; assert_pass "IP forwarding: enabled" "$?"
    [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" == "1" ]]; assert_pass "Reverse path filtering: enabled" "$?"
    [[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" == "1" ]]; assert_pass "ICMP broadcast ignore: enabled" "$?"
    [[ "$(sysctl -n net.ipv4.tcp_syncookies)" == "1" ]]; assert_pass "TCP SYN cookies: enabled" "$?"
    [[ "$(sysctl -n net.ipv4.conf.all.accept_source_route)" == "0" ]]; assert_pass "Source routing: disabled" "$?"
}

test_connectivity() {
    section "Connectivity Tests"
    ping -c 1 -W 1 192.168.1.1 &>/dev/null; assert_pass "LAN1 gateway (192.168.1.1) reachable" "$?"
    ping -c 1 -W 1 192.168.2.1 &>/dev/null; assert_pass "LAN2 gateway (192.168.2.1) reachable" "$?"
    nslookup google.com &>/dev/null || dig google.com &>/dev/null; assert_pass "External DNS working" "$?"
    warn_test "Run 'curl http://$WEB_SERVER' from LAN1 client to verify access"
    warn_test "Run 'curl http://$WEB_SERVER' from LAN2 client (should fail/be blocked)"
}

run_security_scan() {
    section "Quick Security Scan"
    local open_ports; open_ports=$(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -nu | tr '\n' ' ')
    echo -e "  Open ports: ${YELLOW}$open_ports${NC}"
    local unexpected=""
    for port in $open_ports; do
        case $port in 22|53|67|68|80|443) ;; *) unexpected="$unexpected $port" ;; esac
    done
    if [[ -z "$unexpected" ]]; then
        echo -e "  ${GREEN}✅ No unexpected ports${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Unexpected ports:$unexpected${NC}"
    fi
    local ww; ww=$(find /var/www/html -perm -0002 -type f 2>/dev/null | wc -l)
    [[ $ww -eq 0 ]]; assert_pass "No world-writable files in web root" "$?"
}

print_summary() {
    local total=$((PASS + FAIL + WARN))
    local pct=0; [[ $total -gt 0 ]] && pct=$((PASS * 100 / total))

    echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         TEST SUITE RESULTS               ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}✅ Passed:  ${PASS}${NC}                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}❌ Failed:  ${FAIL}${NC}                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}⚠️  Warnings: ${WARN}${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Pass Rate: ${pct}%                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"

    if [[ $FAIL -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 All tests passed!${NC}"
    else
        echo -e "\n${YELLOW}⚠️  $FAIL test(s) failed. Run: sudo ./setup.sh to reconfigure${NC}"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║   🧪 Secure Two-LAN Network Test Suite       ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

[[ $EUID -eq 0 ]] || { echo -e "${RED}Run as root: sudo ./scripts/test-suite.sh${NC}"; exit 1; }

test_network_interfaces
test_dhcp_server
test_web_server
test_firewall
test_security_services
test_sysctl
test_connectivity
run_security_scan
print_summary
exit $FAIL
