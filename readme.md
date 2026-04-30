![Made with Cisco Packet Tracer](https://img.shields.io/badge/Tool-Cisco%20Packet%20Tracer-blue)
![Ubuntu](https://img.shields.io/badge/OS-Ubuntu-orange)
![Apache](https://img.shields.io/badge/WebServer-Apache-red)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen)
# 🔒 Secure Two-LAN Network with DHCP, Web Server & Traffic Monitoring

## 📌 Overview

This project demonstrates the design and implementation of a **secure dual-network (Two-LAN) architecture** using both **Cisco Packet Tracer simulation** and a **real Ubuntu-based environment**.

The network is divided into:

* **LAN1 (Internal Network)** – Trusted users
* **LAN2 (Public/DMZ Network)** – Guests and web server access

The goal is to achieve:

* Secure network segmentation
* Controlled inter-network communication
* Internal web hosting
* Real-time traffic monitoring and logging

This project bridges **theoretical networking concepts** with **practical system implementation**.

---

## 🧠 Key Features

* 🌐 **Dual LAN Segmentation**

  * LAN1 → 192.168.1.0/24 (Internal)
  * LAN2 → 192.168.2.0/24 (DMZ/Public)

* 🔁 **Inter-LAN Routing**

  * Router-based communication between networks

* 📡 **DHCP + Static IP Support**

  * Dynamic IP allocation for clients
  * Static addressing for servers

* 🌍 **Web Server Hosting**

  * Internal HTTP server (Packet Tracer + Apache Ubuntu)

* 🛡️ **Security Isolation**

  * Logical separation of internal and public networks
  * Controlled communication via routing

* 📊 **Traffic Monitoring**

  * Packet capture using tcpdump
  * Log file generation and analysis

* 🧪 **Testing & Validation**

  * Ping tests
  * HTTP access verification
  * Simulation mode packet tracing

---

## 🏗️ Architecture

The system follows a **two-LAN segmented model**:

* LAN1 → Internal users (secure zone)
* LAN2 → Guests + Web Server (DMZ)

All communication passes through a router acting as:

* Gateway
* Security control point

Detailed architecture available in:
👉 

---

## ⚙️ Technologies Used

### 🖥️ Simulation

* Cisco Packet Tracer
* Router (Cisco 2911)
* Switches (2960)
* PCs & Server

### 🐧 Implementation

* Ubuntu Linux
* Apache2 Web Server
* Bash Scripts

### 🔍 Monitoring Tools

* tcpdump
* Wireshark
* Log-based traffic analysis

---

## 🚀 Implementation Highlights

### 🔹 Network Design

* Two separate LANs with distinct IP ranges
* Router configured as default gateway

### 🔹 Server Deployment

* Internal web server hosted in LAN2
* Apache2 setup on Ubuntu

### 🔹 Traffic Monitoring

* Packet capture stored as `.pcap` files
* Logs generated in `/var/log/traffic`

### 🔹 Validation

* Successful ping across LANs
* Web server accessible via browser

All implementation steps are documented in the report 

---

## 🧪 Testing Results

| Test Type              | Result    |
| ---------------------- | --------- |
| Same LAN Communication | ✅ Success |
| Cross-LAN Routing      | ✅ Success |
| Web Server Access      | ✅ Success |
| Traffic Monitoring     | ✅ Active  |

---

## 📂 Project Structure

```
secure-two-lan-network/
│
├── README.md
├── architecture.md
├── troubleshooting.md
├── setup.sh
├── start-monitoring.sh
├── logs/
├── report/
└── packet-tracer-file.pkt
```

---

## 👥 Contributors

### 👩‍💻 Swasthi Kunder — *Project Lead*

* Network design and architecture
* Cisco Packet Tracer configuration
* Ubuntu server setup and testing
* Traffic monitoring implementation

### 👨‍💻 Sakshat S — *Documentation & Contributor*

* Project documentation and report preparation
* README and technical documentation
* Structuring architecture and explanations
* Testing validation support

---

## 🔧 Troubleshooting

Common issues and fixes are documented here:
👉 

Includes:

* DHCP issues
* Apache server errors
* VLAN problems
* Traffic capture failures

---

## 🔮 Future Improvements

* 🔐 Access Control Lists (ACLs)
* 🔥 Firewall integration (ASA / iptables advanced rules)
* 🌍 Internet access with NAT
* 📡 Wireless network integration
* 🚨 Intrusion Detection Systems (IDS)
* 📊 Monitoring dashboard (Grafana / Prometheus)

---

## 📚 References

* Cisco Networking Academy
* Apache HTTP Server Documentation
* Ubuntu Server Docs
* Computer Networking – Tanenbaum

---

## ⭐ Why This Project Stands Out

This is not just a simulation project.
It combines:

✔ Network design
✔ Real-world Linux implementation
✔ Security concepts
✔ Traffic monitoring
✔ Practical validation

Making it a **complete mini network security lab**.

---

## 💬 Final Note

This project reflects a strong foundation in:

* Networking fundamentals
* Cybersecurity principles
* System-level implementation

Built as part of academic coursework — but designed with **real-world relevance**.

---
