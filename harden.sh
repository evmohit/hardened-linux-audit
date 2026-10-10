#!/usr/bin/env bash
#
# Automated Linux Hardening & Audit Script
# Target OS: Debian / Ubuntu / Mint
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="audit_$(date +%Y%m%d_%H%M%S).log"
AUTO_FIX=false

if [[ "${1:-}" == "--fix" ]]; then
    AUTO_FIX=true
fi

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
       log "${RED}[ERROR] This script must be run as root.${NC}"
       exit 1
    fi
}

audit_ssh() {
    log "\n=== [1] Auditing SSH Configuration ==="
    SSHD_CONFIG="/etc/ssh/sshd_config"
    
    if [ -f "$SSHD_CONFIG" ]; then
        if grep -q "^PermitRootLogin no" "$SSHD_CONFIG"; then
            log "${GREEN}[PASS] Root login is explicitly disabled via SSH.${NC}"
        else
            log "${RED}[FAIL] PermitRootLogin is enabled or not explicitly set to 'no'.${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Disabling SSH root login...${NC}"
                sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
                systemctl restart sshd 2>/dev/null || true
                log "${GREEN}[FIXED] SSH root login disabled.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] SSH server not installed (/etc/ssh/sshd_config missing).${NC}"
    fi
}

audit_sysctl() {
    log "\n=== [2] Auditing Kernel Parameters (sysctl) ==="
    
    # TCP SYN Cookies
    SYN_COOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    if [ "$SYN_COOKIES" -eq 1 ]; then
        log "${GREEN}[PASS] TCP SYN Cookies (Flood Protection) enabled.${NC}"
    else
        log "${RED}[FAIL] TCP SYN Cookies disabled.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Enabling TCP SYN Cookies...${NC}"
            sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
            log "${GREEN}[FIXED] TCP SYN Cookies enabled.${NC}"
        fi
    fi

    # ICMP Redirects
    ACCEPT_REDIRECTS=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
    if [ "$ACCEPT_REDIRECTS" -eq 0 ]; then
        log "${GREEN}[PASS] ICMP Redirects are disabled (MITM protection).${NC}"
    else
        log "${RED}[FAIL] ICMP Redirects are allowed.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Disabling ICMP Redirects...${NC}"
            sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null
            log "${GREEN}[FIXED] ICMP Redirects disabled.${NC}"
        fi
    fi
}

audit_ufw() {
    log "\n=== [3] Auditing Firewall (UFW) Status ==="
    
    if command -v ufw >/dev/null 2>&1; then
        UFW_STATUS=$(ufw status | grep -i "status:" | awk '{print $2}')
        if [ "$UFW_STATUS" = "active" ]; then
            log "${GREEN}[PASS] UFW Firewall is ACTIVE.${NC}"
        else
            log "${RED}[FAIL] UFW Firewall is INACTIVE.${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Enabling UFW Firewall with default rules...${NC}"
                ufw default deny incoming >/dev/null
                ufw default allow outgoing >/dev/null
                ufw --force enable >/dev/null
                log "${GREEN}[FIXED] UFW Firewall activated.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] UFW tool is not installed.${NC}"
    fi
}

audit_users() {
    log "\n=== [4] Auditing User Accounts & Passwords ==="
    
    # 1. Check for empty password fields in /etc/shadow
    EMPTY_PASS=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
    if [ -z "$EMPTY_PASS" ]; then
        log "${GREEN}[PASS] No accounts with empty passwords found.${NC}"
    else
        log "${RED}[FAIL] Account(s) with empty password found: ${EMPTY_PASS}${NC}"
    fi

    # 2. Check for unauthorized UID 0 accounts (other than root)
    EXTRA_ROOTS=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
    if [ -z "$EXTRA_ROOTS" ]; then
        log "${GREEN}[PASS] Only 'root' user has UID 0 privileges.${NC}"
    else
        log "${RED}[FAIL] Unauthorized non-root UID 0 account(s) found: ${EXTRA_ROOTS}${NC}"
    fi

    # 3. Check MAX_DAYS password expiration policy in /etc/login.defs & human user accounts
    MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    USER_MAX_EXCEEDED=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read -r u; do awk -F: -v user="$u" '$1 == user && ($5 > 90 || $5 == "") {print $1}' /etc/shadow; done)

    if [ -n "$MAX_DAYS" ] && [ "$MAX_DAYS" -le 90 ] && [ -z "$USER_MAX_EXCEEDED" ]; then
        log "${GREEN}[PASS] Password Max Days policy is compliant (90 days).${NC}"
    else
        log "${RED}[FAIL] Insecure Password Max Days detected (login.defs: ${MAX_DAYS:-99999}, Non-compliant users: ${USER_MAX_EXCEEDED:-none}).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Setting PASS_MAX_DAYS to 90 in /etc/login.defs and updating existing users...${NC}"
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
            
            # Apply 90 days limit to all regular existing human users (UID >= 1000)
            awk -F: '$3 >= 1000 && $1 != "nobody" { print $1 }' /etc/passwd | while read -r user; do
                chage -M 90 "$user"
            done
            log "${GREEN}[FIXED] Password Max Days updated to 90 days for system defaults and existing users.${NC}"
        fi
    fi
}

audit_services_and_perms() {
    log "\n=== [5] Auditing Unnecessary Services & File Permissions ==="

    # 1. Check for insecure/unnecessary services (e.g., telnet, vsftpd, rsh-server)
    INSECURE_SERVICES=("telnet" "vsftpd" "rsh-server" "nis")
    FOUND_SERVICES=()

    for srv in "${INSECURE_SERVICES[@]}"; do
        if systemctl is-active --quiet "$srv" 2>/dev/null; then
            FOUND_SERVICES+=("$srv")
        fi
    done

    if [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
        log "${GREEN}[PASS] No insecure legacy services running.${NC}"
    else
        log "${RED}[FAIL] Insecure active service(s) detected: ${FOUND_SERVICES[*]}${NC}"
        if [ "$AUTO_FIX" = true ]; then
            for srv in "${FOUND_SERVICES[@]}"; do
                log "${YELLOW}[FIXING] Disabling and stopping service: ${srv}...${NC}"
                systemctl disable --now "$srv" >/dev/null 2>&1 || true
            done
            log "${GREEN}[FIXED] Insecure services disabled.${NC}"
        fi
    fi

    # 2. Check permissions on /etc/shadow (Must be 600 or 640)
    SHADOW_PERM=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "000")
    if [ "$SHADOW_PERM" -eq 600 ] || [ "$SHADOW_PERM" -eq 640 ]; then
        log "${GREEN}[PASS] /etc/shadow permissions are secure (${SHADOW_PERM}).${NC}"
    else
        log "${RED}[FAIL] /etc/shadow permissions are insecure (${SHADOW_PERM}, should be 600 or 640).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Setting /etc/shadow permissions to 600...${NC}"
            chmod 600 /etc/shadow
            log "${GREEN}[FIXED] /etc/shadow permissions updated to 600.${NC}"
        fi
    fi

    # 3. Check permissions on /etc/passwd (Must be 644)
    PASSWD_PERM=$(stat -c "%a" /etc/passwd 2>/dev/null || echo "000")
    if [ "$PASSWD_PERM" -eq 644 ]; then
        log "${GREEN}[PASS] /etc/passwd permissions are secure (${PASSWD_PERM}).${NC}"
    else
        log "${RED}[FAIL] /etc/passwd permissions are insecure (${PASSWD_PERM}, should be 644).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Setting /etc/passwd permissions to 644...${NC}"
            chmod 644 /etc/passwd
            log "${GREEN}[FIXED] /etc/passwd permissions updated to 644.${NC}"
        fi
    fi
}

audit_logging_and_updates() {
    log "\n=== [6] Auditing System Logging & Security Updates ==="

    # 1. Audit auditd service (Linux Audit Framework)
    if systemctl is-active --quiet auditd 2>/dev/null; then
        log "${GREEN}[PASS] Audit daemon (auditd) is active.${NC}"
    else
        log "${RED}[FAIL] Audit daemon (auditd) is inactive or missing.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Installing/enabling auditd...${NC}"
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y auditd >/dev/null 2>&1 || true
            systemctl enable --now auditd >/dev/null 2>&1 || true
            log "${GREEN}[FIXED] auditd installed and activated.${NC}"
        fi
    fi

    # 2. Audit rsyslog service
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        log "${GREEN}[PASS] System logging daemon (rsyslog) is active.${NC}"
    else
        log "${RED}[FAIL] System logging daemon (rsyslog) is inactive or missing.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Enabling rsyslog...${NC}"
            systemctl enable --now rsyslog >/dev/null 2>&1 || true
            log "${GREEN}[FIXED] rsyslog service activated.${NC}"
        fi
    fi

    # 3. Audit /var/log/syslog file permissions (Must be 640 or 600)
    if [ -f /var/log/syslog ]; then
        LOG_PERM=$(stat -c "%a" /var/log/syslog 2>/dev/null || echo "000")
        if [ "$LOG_PERM" -eq 640 ] || [ "$LOG_PERM" -eq 600 ]; then
            log "${GREEN}[PASS] /var/log/syslog permissions are secure (${LOG_PERM}).${NC}"
        else
            log "${RED}[FAIL] /var/log/syslog permissions are insecure (${LOG_PERM}, should be 640 or 600).${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Setting /var/log/syslog permissions to 640...${NC}"
                chmod 640 /var/log/syslog
                log "${GREEN}[FIXED] /var/log/syslog permissions set to 640.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] /var/log/syslog does not exist on this system.${NC}"
    fi

    # 4. Audit unattended-upgrades package
    if dpkg -s unattended-upgrades >/dev/null 2>&1; then
        log "${GREEN}[PASS] Unattended-upgrades package is installed.${NC}"
    else
        log "${RED}[FAIL] Unattended-upgrades package is not installed.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Installing unattended-upgrades...${NC}"
            apt-get install -y unattended-upgrades >/dev/null 2>&1 || true
            log "${GREEN}[FIXED] Unattended-upgrades installed.${NC}"
        fi
    fi
}

audit_integrity_and_ports() {
    log "\n=== [7] Auditing File System Integrity & Network Ports ==="

    # 1. Audit SUID / SGID Files
    log "${YELLOW}[INFO] Scanning for SUID files in standard system paths...${NC}"
    SUID_FILES=$(find /bin /sbin /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [ "$SUID_FILES" -gt 0 ]; then
        log "${GREEN}[PASS] SUID/SGID audit complete (${SUID_FILES} executables detected).${NC}"
    else
        log "${YELLOW}[WARN] No SUID/SGID files found in binary paths.${NC}"
    fi

    # 2. Audit World-Writable Files
    log "${YELLOW}[INFO] Auditing for world-writable files...${NC}"
    WORLD_WRITABLE=$(find / -xdev -type f \( -perm -0002 -o -perm -0022 \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | head -n 5)
    if [ -z "$WORLD_WRITABLE" ]; then
        log "${GREEN}[PASS] No risky world-writable files detected.${NC}"
    else
        log "${RED}[FAIL] World-writable file(s) found outside /tmp: ${WORLD_WRITABLE}${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Removing world-write permissions from detected files...${NC}"
            find / -xdev -type f \( -perm -0002 -o -perm -0022 \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -exec chmod o-w {} + 2>/dev/null || true
            log "${GREEN}[FIXED] World-write permissions revoked.${NC}"
        fi
    fi

    # 3. Audit Open Listening Ports
    log "${YELLOW}[INFO] Checking listening TCP/UDP network ports...${NC}"
    if command -v ss >/dev/null 2>&1; then
        LISTEN_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d':' -f2 | sort -u | tr '\n' ' ')
        log "${GREEN}[PASS] Active listening port(s): ${LISTEN_PORTS:-none}${NC}"
    else
        log "${YELLOW}[WARN] 'ss' command not available to check ports.${NC}"
    fi
}

main() {
    check_root
    log "Starting Security Baseline Audit (Fix Mode: ${AUTO_FIX})..."
    audit_ssh
    audit_sysctl
    audit_ufw
    audit_users
    audit_services_and_perms
    audit_logging_and_updates
    audit_integrity_and_ports
    log "\nTask complete. Log written to ${LOG_FILE}"
}

main "$@"
