# 🔧 Troubleshooting Guide

## Quick Diagnostics

```bash
# Run automated test suite first
sudo ./scripts/test-suite.sh

# Check all services
sudo systemctl status isc-dhcp-server apache2 fail2ban

# View setup log
sudo tail -f /var/log/secure-lan-setup.log
```

---

## 🔴 DHCP Not Assigning Addresses

**Symptoms:** Clients get APIPA (169.254.x.x) or no IP

```bash
# 1. Check service
sudo systemctl status isc-dhcp-server

# 2. Check logs
sudo journalctl -u isc-dhcp-server -n 50

# 3. Verify interface binding
cat /etc/default/isc-dhcp-server

# 4. Test config syntax
sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf

# 5. Check interface is UP
ip addr show eth0.10

# Fix: bring interfaces up before DHCP restart
sudo ip link set eth0.10 up
sudo ip link set eth0.20 up
sudo systemctl restart isc-dhcp-server
```

---

## 🔴 Web Server Unreachable from LAN1

**Symptoms:** curl times out or refuses connection

```bash
# 1. Check Apache
sudo systemctl status apache2

# 2. Test local
curl -v http://localhost/

# 3. Check UFW rules
sudo ufw status verbose

# 4. Check iptables port 80
sudo iptables -L -n -v | grep 80

# 5. Check Apache config
sudo apache2ctl configtest

# Fix
sudo ufw allow from 192.168.1.0/24 to any port 80 proto tcp
sudo ufw reload
sudo systemctl restart apache2
```

---

## 🔴 VLAN Interfaces Not Created

**Symptoms:** eth0.10/eth0.20 not in `ip addr`

```bash
# 1. Check 8021q module
lsmod | grep 8021q

# 2. Load manually
sudo modprobe 8021q

# 3. Check base interface name
ip link show

# 4. Create manually
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip addr add 192.168.1.1/24 dev eth0.10
sudo ip link set eth0.10 up
```

---

## 🔴 No Traffic Capture

**Symptoms:** .pcap files empty or tcpdump reports no packets

```bash
# 1. Enable promiscuous mode
sudo ip link set eth0.10 promisc on

# 2. Test manually
sudo tcpdump -i eth0.10 -v

# 3. Add user to wireshark group
sudo usermod -aG wireshark $USER
```

---

## 🔴 LAN2 Can Access LAN1

**Symptoms:** Cross-LAN traffic succeeds when it should be blocked

```bash
# 1. Check FORWARD rules
sudo iptables -L FORWARD -n -v

# 2. Re-apply firewall
sudo ./scripts/firewall-setup.sh

# 3. Verify DROP rules with line numbers
sudo iptables -L FORWARD -n --line-numbers
```

---

## 🔴 Python Scripts Fail

**Symptoms:** ImportError or ModuleNotFoundError

```bash
# Install dependencies
pip3 install scapy colorama tabulate psutil schedule

# Run with root
sudo python3 scripts/traffic-analyzer.py

# Check Python version (must be 3.8+)
python3 --version
```

---

## Log File Locations

| Log              | Location                                        |
|------------------|-------------------------------------------------|
| Setup log        | `/var/log/secure-lan-setup.log`                 |
| DHCP server      | `journalctl -u isc-dhcp-server`                 |
| Apache access    | `/var/log/apache2/access.log`                   |
| Apache error     | `/var/log/apache2/error.log`                    |
| Firewall         | `/var/log/syslog` (grep "IPT-")                 |
| Traffic captures | `/var/log/traffic/*.pcap`                       |
| Security alerts  | `/var/log/security-events/traffic-alerts.log`   |
| DHCP alerts      | `/var/log/dhcp-monitor/alerts.log`              |
| Security reports | `/var/log/security-reports/`                    |
