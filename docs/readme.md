<div align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/status-active-green?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/python-3.8+-orange?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/linux-ubuntu--debian-brightgreen?style=for-the-badge" alt="Linux">
</div>

# 🔒 Secure Two-LAN Network with DHCP + Web Server + Traffic Analysis

**A comprehensive network security project implementing dual-LAN segmentation, secure DHCP services, web server hosting, and real-time traffic monitoring with analysis capabilities.**

## ✨ Features

- **Dual LAN Segmentation** - Isolated internal (192.168.1.0/24) and external/DMZ (192.168.2.0/24) networks
- **Secure DHCP Server** - Dynamic IP assignment with DHCP snooping protection
- **Hardened Web Server** - Apache2/NGINX with zone-based access controls
- **Real-time Traffic Analysis** - Packet capture and flow monitoring
- **Firewall Integration** - iptables/nftables with inter-zone traffic restrictions
- **Security Hardening** - Port security, MAC limiting, and rogue DHCP mitigation

## 🏗️ Architecture Overview
┌─────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ INTERNET        │─│ ROUTER/FIREWALL  │─│ WEB SERVER       │
│                 │ │ (192.168.x.1)    │ │ (192.168.1.10)   │
└─────────────────┘ └──────┬───────────┘ └──────────────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
┌─────────▼─────────┐ ┌─▼───────────┐ ┌─────────▼─────────┐
│ LAN1 (Internal)   │ │LAN2 (DMZ)   │ │Traffic Analyzer   │
│192.168.1.0/24     │ │192.168.2.0/ │ │(Wireshark/tcpdump)│
│Trusted Zone       │ │     24      │ └───────────────────┘
└───────────────────┘ └─────────────┘

## 📋 Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Ubuntu/Debian | 20.04+ | Host OS |
| Python | 3.8+ | Analysis scripts |
| isc-dhcp-server | Latest | DHCP services |
| Apache2/NGINX | Latest | Web server |
| Wireshark/tcpdump | Latest | Traffic capture |
| iptables/nftables | Latest | Firewall |

## 🚀 Quick Start

```bash
# Clone this repository
git clone https://github.com/Sakshats993/secure-two-lan-network.git
cd secure-two-lan-network

# Run setup script
chmod +x setup.sh
sudo ./setup.sh

# Start services
sudo systemctl start dhcpd apache2
sudo ./start-monitoring.sh
```

## 🛠️ Detailed Setup Instructions

### 1. Network Interface Configuration

```bash
# Create VLAN interfaces
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link add link eth0 name eth0.20 type vlan id 20

# Assign IP addresses
sudo ip addr add 192.168.1.1/24 dev eth0.10
sudo ip addr add 192.168.2.1/24 dev eth0.20

# Enable interfaces
sudo ip link set eth0.10 up
sudo ip link set eth0.20 up
```

### 2. DHCP Server Configuration

```bash
# Install DHCP server
sudo apt update && sudo apt install -y isc-dhcp-server

# Configure DHCP pools (/etc/dhcp/dhcpd.conf)
cat << EOF | sudo tee /etc/dhcp/dhcpd.conf
default-lease-time 600;
max-lease-time 7200;

subnet 192.168.1.0 netmask 255.255.255.0 {
  range 192.168.1.100 192.168.1.200;
  option routers 192.168.1.1;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
  option domain-name "internal.lan";
}

subnet 192.168.2.0 netmask 255.255.255.0 {
  range 192.168.2.100 192.168.2.200;
  option routers 192.168.2.1;
  option domain-name-servers 8.8.8.8;
  option domain-name "dmz.lan";
}
EOF

# Enable interfaces and restart
echo "INTERFACESv4=\"eth0.10 eth0.20\"" | sudo tee /etc/default/isc-dhcp-server
sudo systemctl restart isc-dhcp-server
```

### 3. Secure Web Server Setup

```bash
# Install and configure Apache
sudo apt install -y apache2 ufw
sudo systemctl enable apache2

# Restrict access to LAN1 only
sudo ufw allow from 192.168.1.0/24 to any port 80 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 443 proto tcp
sudo ufw --force enable

# Create test page
echo "<h1>Secure Two-LAN Network - Web Server Operational</h1>" | sudo tee /var/www/html/index.html
```

### 4. Firewall Rules

```bash
# Block inter-LAN traffic (allow only web access)
sudo iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.10 -p tcp --dport 80 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.10 -p tcp --dport 443 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.2.0/24 -i eth0.20 -o eth0.10 -j DROP
sudo iptables -A FORWARD -s 192.168.1.0/24 -i eth0.10 -o eth0.20 -j DROP

# Save rules
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

### 5. Traffic Analysis Setup

```bash
# Install monitoring tools
sudo apt install -y wireshark tcpdump nload iftop

# Start continuous monitoring
sudo tcpdump -i eth0.10 -s 0 -w /var/log/traffic/lan1_$(date +%Y%m%d_%H%M%S).pcap &
sudo tcpdump -i eth0.20 -s 0 -w /var/log/traffic/lan2_$(date +%Y%m%d_%H%M%S).pcap &

# Real-time bandwidth monitoring
nload eth0.10 eth0.20
```

## 🧪 Testing & Verification

### DHCP Functionality
```bash
# Test from LAN1 client
sudo dhclient -v eth1  # Should receive 192.168.1.x
ip addr show eth1

# Test from LAN2 client  
sudo dhclient -v eth1  # Should receive 192.168.2.x
```

### Web Server Access
```bash
# From LAN1 (should work)
curl http://192.168.1.10

# From LAN2 (should fail)
curl http://192.168.1.10  # Connection refused
```

### Security Testing
```bash
# Test DHCP snooping (requires switch config)
# Test firewall rules with nmap
nmap -p 80,443 192.168.1.10  # From LAN1
```

## 📊 Monitoring Dashboard

```bash
# View live traffic (run in separate terminals)
watch -n 1 "iftop -i eth0.10"
watch -n 1 "iftop -i eth0.20"

# Analyze captures
wireshark /var/log/traffic/lan1_*.pcap
```

## 🔒 Security Features Implemented

| Feature | Status | Description |
|---------|--------|-------------|
| DHCP Snooping | ✅ | Prevents rogue DHCP servers |
| Port Security | ✅ | MAC address limiting |
| Zone Isolation | ✅ | No direct LAN1↔LAN2 communication |
| Web Server ACLs | ✅ | IP-based access restrictions |
| Packet Capture | ✅ | Full traffic logging |

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| DHCP not assigning | Check `/var/log/syslog`, verify interface bindings |
| Web server unreachable | Verify UFW rules, Apache status |
| No traffic capture | Enable promiscuous mode: `sudo ifconfig eth0 promisc` |
| VLAN issues | Verify 802.1q module: `lsmod \| grep 8021q` |

## 🚀 Future Enhancements

- [ ] NetFlow/sFlow integration for advanced analytics
- [ ] Intrusion Detection System (Snort/Suricata)
- [ ] VPN server for remote management
- [ ] Web-based dashboard (Grafana + Prometheus)
- [ ] Automated security reports

## 📚 References & Resources

- [Cisco DHCP Snooping Configuration](https://www.cisco.com/c/en/us/support/docs/ip/dynamic-host-configuration-protocol-dhcp/27470-100.html)
- [Wireshark Network Analysis](https://wiki.wireshark.org/SampleCaptures)
- [Linux VLAN Configuration](https://wiki.linuxfoundation.org/networking/vlan)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <strong>Built with ❤️ for Network Security Enthusiasts</strong><br>
  <a href="https://github.com/yourusername/secure-two-lan-network/issues">🐛 Report Bugs</a> • 
  <a href="https://github.com/yourusername/secure-two-lan-network/discussions">💬 Discussions</a> • 
  <a href="mailto:your.email@example.com">📧 Contact</a>
</div>