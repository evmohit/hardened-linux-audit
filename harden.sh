#!/usr/bin/env bash
#
# Automated Linux Hardening & Audit Script
# Target OS: Debian / Ubuntu / Mint
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

LOG_FILE="audit_$(date +%Y%m%d_%H%M%S).log"

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
    
    if grep -q "^PermitRootLogin no" "$SSHD_CONFIG"; then
        log "${GREEN}[PASS] Root login is disabled via SSH.${NC}"
    else
        log "${RED}[FAIL] PermitRootLogin is enabled or not explicitly set to 'no'.${NC}"
    fi
}

main() {
    check_root
    log "Starting Security Baseline Audit..."
    audit_ssh
    log "\nAudit complete. Log written to ${LOG_FILE}"
}

main "$@"
