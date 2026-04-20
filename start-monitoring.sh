#!/bin/bash
# =============================================================================
# Start Network Traffic Monitoring
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_DIR="/var/log/traffic"
PID_FILE="/var/run/lan-monitoring.pids"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LAN1_IF="eth0.10"
LAN2_IF="eth0.20"

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       📡 Network Traffic Monitoring Starting         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() { [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }

check_interfaces() {
    ip link show "$LAN1_IF" &>/dev/null || LAN1_IF="eth0"
    ip link show "$LAN2_IF" &>/dev/null || LAN2_IF="eth0"
    echo -e "${GREEN}✅ Monitoring: $LAN1_IF, $LAN2_IF${NC}"
}

start_captures() {
    mkdir -p "$LOG_DIR"
    > "$PID_FILE"
    echo -e "${BLUE}▶ Starting tcpdump captures...${NC}"

    tcpdump -i "$LAN1_IF" -s 0 -w "${LOG_DIR}/lan1_${TIMESTAMP}.pcap" \
        -C 100 -W 5 2>/dev/null &
    echo $! >> "$PID_FILE"
    echo -e "${GREEN}  ✅ LAN1 capture → ${LOG_DIR}/lan1_${TIMESTAMP}.pcap${NC}"

    tcpdump -i "$LAN2_IF" -s 0 -w "${LOG_DIR}/lan2_${TIMESTAMP}.pcap" \
        -C 100 -W 5 2>/dev/null &
    echo $! >> "$PID_FILE"
    echo -e "${GREEN}  ✅ LAN2 capture → ${LOG_DIR}/lan2_${TIMESTAMP}.pcap${NC}"

    tcpdump -i any -s 0 port 67 or port 68 \
        -w "${LOG_DIR}/dhcp_${TIMESTAMP}.pcap" 2>/dev/null &
    echo $! >> "$PID_FILE"
    echo -e "${GREEN}  ✅ DHCP capture → ${LOG_DIR}/dhcp_${TIMESTAMP}.pcap${NC}"
}

start_live_analysis() {
    echo -e "\n${BLUE}▶ Starting Python traffic analyzer...${NC}"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/scripts/traffic-analyzer.py" ]]; then
        python3 "${SCRIPT_DIR}/scripts/traffic-analyzer.py" \
            --interface "$LAN1_IF" --log-dir "$LOG_DIR" --daemon &
        echo $! >> "$PID_FILE"
        echo -e "${GREEN}  ✅ Traffic analyzer PID: $!${NC}"
    fi
}

print_status() {
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          📊 Monitoring Active                        ║"
    echo "╠══════════════════════════════════════════════════════╣"
    printf "║  %-52s║\n" "  Capture Files: $LOG_DIR"
    printf "║  %-52s║\n" "  PID File: $PID_FILE"
    printf "║  %-52s║\n" "  Stop: sudo ./stop-monitoring.sh"
    printf "║  %-52s║\n" "  Live View: sudo iftop -i $LAN1_IF"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

main() {
    print_banner
    check_root
    check_interfaces
    start_captures
    start_live_analysis
    print_status
}

main "$@"
