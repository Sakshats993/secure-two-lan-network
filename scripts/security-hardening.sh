#!/bin/bash
# =============================================================================
# Security Hardening Script
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}  Applying security hardening measures...${NC}"

# ─── Fail2Ban ─────────────────────────────────────────────────────────────────
if command -v fail2ban-server &>/dev/null; then
    cat > /etc/fail2ban/jail.local << 'F2B_EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 7200

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true
F2B_EOF
    systemctl enable fail2ban
    systemctl restart fail2ban
    echo -e "${GREEN}  ✅ Fail2Ban configured${NC}"
fi

# ─── Disable Unnecessary Services ────────────────────────────────────────────
for svc in avahi-daemon cups bluetooth whoopsie; do
    if systemctl list-unit-files | grep -q "$svc"; then
        systemctl disable "$svc" 2>/dev/null || true
        systemctl stop "$svc" 2>/dev/null || true
        echo -e "${GREEN}  ✅ Disabled: $svc${NC}"
    fi
done

# ─── SSH Hardening ────────────────────────────────────────────────────────────
SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak.$(date +%Y%m%d)"
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' "$SSH_CONFIG"
    sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 300/' "$SSH_CONFIG"
    sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 2/' "$SSH_CONFIG"
    grep -q "^Protocol" "$SSH_CONFIG" || echo "Protocol 2" >> "$SSH_CONFIG"
    grep -q "^LoginGraceTime" "$SSH_CONFIG" || echo "LoginGraceTime 60" >> "$SSH_CONFIG"
    sed -i 's/X11Forwarding yes/X11Forwarding no/' "$SSH_CONFIG"
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
    echo -e "${GREEN}  ✅ SSH hardening applied${NC}"
fi

# ─── Apache Security Hardening ───────────────────────────────────────────────
if command -v apache2 &>/dev/null; then
    cat > /etc/apache2/conf-available/security-hardening.conf << 'APACHE_SEC'
ServerTokens Prod
ServerSignature Off
TraceEnable Off

<FilesMatch "(^\.ht|\.git|\.env|\.config)">
    Require all denied
</FilesMatch>

Options -Indexes
Header always set X-Frame-Options SAMEORIGIN
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options nosniff
LimitRequestBody 10485760
Timeout 60
KeepAliveTimeout 5
APACHE_SEC
    a2enconf security-hardening 2>/dev/null || true
    systemctl reload apache2 2>/dev/null || true
    echo -e "${GREEN}  ✅ Apache security hardening applied${NC}"
fi

# ─── File Permissions ─────────────────────────────────────────────────────────
chmod 640 /var/log/syslog 2>/dev/null || true
chmod 640 /var/log/auth.log 2>/dev/null || true
chmod 600 /etc/dhcp/dhcpd.conf 2>/dev/null || true

# ─── Audit Logging ────────────────────────────────────────────────────────────
if command -v auditd &>/dev/null; then
    cat > /etc/audit/rules.d/secure-lan.rules << 'AUDIT_EOF'
-w /etc/network -p wa -k network-config
-w /etc/dhcp -p wa -k dhcp-config
-w /etc/apache2 -p wa -k webserver-config
-w /etc/iptables -p wa -k firewall-config
-w /var/log/auth.log -p wa -k auth-log
-w /var/lib/dhcp -p wa -k dhcp-leases
-a always,exit -F arch=b64 -S execve -k exec-commands
AUDIT_EOF
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    echo -e "${GREEN}  ✅ Audit logging configured${NC}"
fi

echo -e "\n${GREEN}  ✅ Security hardening complete${NC}"
