#!/bin/bash
# =============================================================================
# Stop Network Traffic Monitoring
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PID_FILE="/var/run/lan-monitoring.pids"
LOG_DIR="/var/log/traffic"

echo -e "${CYAN}🛑 Stopping network monitoring...${NC}"

if [[ -f "$PID_FILE" ]]; then
    while IFS= read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo -e "${GREEN}  ✅ Stopped PID: $pid${NC}"
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

pkill -f tcpdump 2>/dev/null && echo -e "${GREEN}  ✅ Stopped tcpdump${NC}" || true
pkill -f traffic-analyzer.py 2>/dev/null && echo -e "${GREEN}  ✅ Stopped traffic analyzer${NC}" || true

if ls "${LOG_DIR}"/*.pcap 2>/dev/null | head -1 > /dev/null; then
    echo -e "\n${CYAN}📊 Capture files:${NC}"
    ls -lh "${LOG_DIR}"/*.pcap 2>/dev/null | awk '{print "  " $5 "\t" $9}'
    echo -e "\n  Analyze with: wireshark ${LOG_DIR}/*.pcap"
fi

echo -e "\n${GREEN}✅ Monitoring stopped${NC}"
