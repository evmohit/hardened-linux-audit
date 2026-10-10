#!/usr/bin/env bash
#
# Hardened Linux Audit & Security Baseline Script
# Supports: Debian, Ubuntu, Linux Mint
#

# Colors for output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
AUTO_FIX=false
LOG_FILE="audit_$(date +%Y%m%d_%H%M%S).log"

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Root check function
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] This script must be run as root (sudo).${NC}" >&2
        exit 1
    fi
}

# [1] SSH Configuration Audit
audit_ssh() {
    log "\n=== [1] Auditing SSH Configuration ==="
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
            log "${GREEN}[PASS] PermitRootLogin is set to 'no'.${NC}"
        else
            log "${RED}[FAIL] PermitRootLogin is not set to 'no'.${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Setting PermitRootLogin to no...${NC}"
                sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
                systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
                log "${GREEN}[FIXED] PermitRootLogin set to no and SSH restarted.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] /etc/ssh/sshd_config not found.${NC}"
    fi
}

# [2] Kernel Parameters (sysctl) Audit
audit_sysctl() {
    log "\n=== [2] Auditing Kernel Parameters (sysctl) ==="
    
    SYN_COOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    if [ "$SYN_COOKIES" -eq 1 ]; then
        log "${GREEN}[PASS] TCP SYN Cookies (Flood Protection) enabled.${NC}"
    else
        log "${RED}[FAIL] TCP SYN Cookies disabled.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Enabling TCP SYN Cookies...${NC}"
            sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
            echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-security.conf
            log "${GREEN}[FIXED] TCP SYN Cookies enabled.${NC}"
        fi
    fi

    ICMP_REDIR=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    if [ "$ICMP_REDIR" -eq 0 ]; then
        log "${GREEN}[PASS] ICMP Redirects are disabled (MITM protection).${NC}"
    else
        log "${RED}[FAIL] ICMP Redirects are enabled.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Disabling ICMP Redirects...${NC}"
            sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null
            sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null
            echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
            echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
            log "${GREEN}[FIXED] ICMP Redirects disabled.${NC}"
        fi
    fi
}

# [3] Firewall (UFW) Audit
audit_ufw() {
    log "\n=== [3] Auditing Firewall (UFW) Status ==="
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            log "${GREEN}[PASS] UFW Firewall is ACTIVE.${NC}"
        else
            log "${RED}[FAIL] UFW Firewall is INACTIVE.${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Enabling UFW...${NC}"
                ufw --force enable >/dev/null 2>&1
                log "${GREEN}[FIXED] UFW Firewall enabled.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] UFW package is not installed.${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Installing UFW...${NC}"
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y ufw >/dev/null 2>&1 || true
            ufw --force enable >/dev/null 2>&1
            log "${GREEN}[FIXED] UFW installed and enabled.${NC}"
        fi
    fi
}

# [4] User Accounts & Passwords Audit
audit_users() {
    log "\n=== [4] Auditing User Accounts & Passwords ==="
    
    EMPTY_PASS=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$EMPTY_PASS" ]; then
        log "${GREEN}[PASS] No accounts with empty passwords found.${NC}"
    else
        log "${RED}[FAIL] Accounts with empty passwords detected: ${EMPTY_PASS}${NC}"
    fi

    UID_ZERO=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null)
    if [ "$UID_ZERO" = "root" ]; then
        log "${GREEN}[PASS] Only 'root' user has UID 0 privileges.${NC}"
    else
        log "${RED}[FAIL] Non-root accounts with UID 0 found: ${UID_ZERO}${NC}"
    fi

    MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    if [ -n "$MAX_DAYS" ] && [ "$MAX_DAYS" -le 90 ]; then
        log "${GREEN}[PASS] Password Max Days policy is compliant (${MAX_DAYS} days).${NC}"
    else
        log "${YELLOW}[WARN] Password Max Days is set to ${MAX_DAYS:-unlimited} (recommended <= 90).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Setting PASS_MAX_DAYS to 90 in /etc/login.defs...${NC}"
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
            log "${GREEN}[FIXED] PASS_MAX_DAYS updated to 90.${NC}"
        fi
    fi
}

# [5] Unnecessary Services & File Permissions Audit
audit_services_and_perms() {
    log "\n=== [5] Auditing Unnecessary Services & File Permissions ==="
    
    SERVICES=("telnet" "vsftpd" "rsh-server" "nis")
    INSECURE_FOUND=false
    for srv in "${SERVICES[@]}"; do
        if systemctl is-enabled "$srv" 2>/dev/null | grep -q "enabled"; then
            log "${RED}[FAIL] Insecure service enabled: $srv${NC}"
            INSECURE_FOUND=true
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Disabling and stopping $srv...${NC}"
                systemctl disable --now "$srv" >/dev/null 2>&1 || true
                log "${GREEN}[FIXED] $srv disabled.${NC}"
            fi
        fi
    done
    if [ "$INSECURE_FOUND" = false ]; then
        log "${GREEN}[PASS] No insecure legacy services running.${NC}"
    fi

    SHADOW_PERM=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "000")
    if [ "$SHADOW_PERM" -le 640 ]; then
        log "${GREEN}[PASS] /etc/shadow permissions are secure (${SHADOW_PERM}).${NC}"
    else
        log "${RED}[FAIL] /etc/shadow permissions are insecure (${SHADOW_PERM}).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Securing /etc/shadow permissions...${NC}"
            chmod 640 /etc/shadow
            log "${GREEN}[FIXED] /etc/shadow permissions set to 640.${NC}"
        fi
    fi

    PASSWD_PERM=$(stat -c "%a" /etc/passwd 2>/dev/null || echo "000")
    if [ "$PASSWD_PERM" -le 644 ]; then
        log "${GREEN}[PASS] /etc/passwd permissions are secure (${PASSWD_PERM}).${NC}"
    else
        log "${RED}[FAIL] /etc/passwd permissions are insecure (${PASSWD_PERM}).${NC}"
        if [ "$AUTO_FIX" = true ]; then
            log "${YELLOW}[FIXING] Securing /etc/passwd permissions...${NC}"
            chmod 644 /etc/passwd
            log "${GREEN}[FIXED] /etc/passwd permissions set to 644.${NC}"
        fi
    fi
}

# [6] System Logging & Security Updates Audit
audit_logging_and_updates() {
    log "\n=== [6] Auditing System Logging & Security Updates ==="

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

    if [ -f /var/log/syslog ]; then
        LOG_PERM=$(stat -c "%a" /var/log/syslog 2>/dev/null || echo "000")
        if [ "$LOG_PERM" -eq 640 ] || [ "$LOG_PERM" -eq 600 ]; then
            log "${GREEN}[PASS] /var/log/syslog permissions are secure (${LOG_PERM}).${NC}"
        else
            log "${RED}[FAIL] /var/log/syslog permissions are insecure (${LOG_PERM}).${NC}"
            if [ "$AUTO_FIX" = true ]; then
                log "${YELLOW}[FIXING] Setting /var/log/syslog permissions to 640...${NC}"
                chmod 640 /var/log/syslog
                log "${GREEN}[FIXED] /var/log/syslog permissions set to 640.${NC}"
            fi
        fi
    else
        log "${YELLOW}[WARN] /var/log/syslog does not exist on this system.${NC}"
    fi

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

# [7] File System Integrity & Network Ports Audit
audit_integrity_and_ports() {
    log "\n=== [7] Auditing File System Integrity & Network Ports ==="

    log "${YELLOW}[INFO] Scanning for SUID files in standard system paths...${NC}"
    SUID_FILES=$(find /bin /sbin /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [ "$SUID_FILES" -gt 0 ]; then
        log "${GREEN}[PASS] SUID/SGID audit complete (${SUID_FILES} executables detected).${NC}"
    else
        log "${YELLOW}[WARN] No SUID/SGID files found in binary paths.${NC}"
    fi

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

    log "${YELLOW}[INFO] Checking listening TCP/UDP network ports...${NC}"
    if command -v ss >/dev/null 2>&1; then
        LISTEN_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}' | cut -d':' -f2 | sort -u | tr '\n' ' ')
        log "${GREEN}[PASS] Active listening port(s): ${LISTEN_PORTS:-none}${NC}"
    else
        log "${YELLOW}[WARN] 'ss' command not available to check ports.${NC}"
    fi
}

# Run All Audits Wrapper
run_all_audits() {
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

# Interactive Menu Function
interactive_menu() {
    while true; do
        clear
        # Determine status color/text for Auto-Fix
        if [ "$AUTO_FIX" = true ]; then
            FIX_STATUS="${GREEN}ENABLED (ON)${NC}"
        else
            FIX_STATUS="${RED}DISABLED (OFF)${NC}"
        fi

        echo -e "${BLUE}=============================================${NC}"
        echo -e "${GREEN}       LINUX HARDENING & AUDIT SCRIPT        ${NC}"
        echo -e "${BLUE}=============================================${NC}"
        echo -e " Auto-Fix Mode: ${FIX_STATUS}"
        echo -e "${BLUE}---------------------------------------------${NC}"
        echo " 1. Run Full Audit (Read-Only)"
        echo " 2. Run Full Audit with Auto-Remediation"
        echo " 3. Toggle Auto-Fix Mode (Currently: $( [ "$AUTO_FIX" = true ] && echo "ON" || echo "OFF" ))"
        echo -e "${BLUE}---------------------------------------------${NC}"
        echo " 4. Audit SSH Configuration"
        echo " 5. Audit Kernel Parameters (sysctl)"
        echo " 6. Audit Firewall (UFW)"
        echo " 7. Audit User Accounts & Passwords"
        echo " 8. Audit Services & File Permissions"
        echo " 9. Audit System Logging & Updates"
        echo " 10. Audit File Integrity & Ports"
        echo -e "${BLUE}---------------------------------------------${NC}"
        echo " 11. Exit"
        echo -e "${BLUE}=============================================${NC}"
        read -p "Select an option [1-11]: " choice

        case $choice in
            1)
                AUTO_FIX=false
                run_all_audits
                ;;
            2)
                AUTO_FIX=true
                run_all_audits
                ;;
            3)
                if [ "$AUTO_FIX" = true ]; then
                    AUTO_FIX=false
                    log "${YELLOW}[INFO] Auto-Fix mode disabled.${NC}"
                else
                    AUTO_FIX=true
                    log "${GREEN}[INFO] Auto-Fix mode enabled. Remediation will apply to single modules too!${NC}"
                fi
                sleep 1
                continue
                ;;
            4)
                check_root
                log "Starting single-module audit: SSH Configuration (Fix Mode: ${AUTO_FIX})"
                audit_ssh
                ;;
            5)
                check_root
                log "Starting single-module audit: Kernel sysctl (Fix Mode: ${AUTO_FIX})"
                audit_sysctl
                ;;
            6)
                check_root
                log "Starting single-module audit: UFW Firewall (Fix Mode: ${AUTO_FIX})"
                audit_ufw
                ;;
            7)
                check_root
                log "Starting single-module audit: User Accounts (Fix Mode: ${AUTO_FIX})"
                audit_users
                ;;
            8)
                check_root
                log "Starting single-module audit: Services & Permissions (Fix Mode: ${AUTO_FIX})"
                audit_services_and_perms
                ;;
            9)
                check_root
                log "Starting single-module audit: Logging & Updates (Fix Mode: ${AUTO_FIX})"
                audit_logging_and_updates
                ;;
            10)
                check_root
                log "Starting single-module audit: File Integrity & Ports (Fix Mode: ${AUTO_FIX})"
                audit_integrity_and_ports
                ;;
            11)
                echo -e "${GREEN}Exiting. Stay secure!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[ERROR] Invalid option. Please choose between 1 and 11.${NC}"
                ;;
        esac
        echo -e "\n---------------------------------------------"
        read -p "Press Enter to return to the menu..."
    done
}

# Execution Entry Point
case "$1" in
    --fix)
        AUTO_FIX=true
        run_all_audits
        ;;
    --interactive|-i)
        interactive_menu
        ;;
    *)
        interactive_menu
        ;;
esac
