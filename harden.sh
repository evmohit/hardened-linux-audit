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

# Check for --fix flag
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

main() {
    check_root
    log "Starting Security Baseline Audit (Fix Mode: ${AUTO_FIX})..."
    audit_ssh
    audit_sysctl
    audit_ufw
    log "\nTask complete. Log written to ${LOG_FILE}"
}

main "$@"
