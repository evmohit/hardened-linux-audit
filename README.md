# Hardened Linux Audit & Security Baseline

Automated Bash script to audit and harden Debian, Ubuntu, and Linux Mint systems against common security baseline configurations.

## Features
- **SSH Configuration:** Root login policy audit and auto-remediation.
- **Kernel Hardening (`sysctl`):** TCP SYN flood protection and ICMP redirect checks/remediation.
- **Firewall (`ufw`):** Uncomplicated Firewall status check and automated rule enforcement.

## Usage

```bash
# Make script executable
chmod +x harden.sh

# Run security audit (Audit mode)
sudo ./harden.sh

# Run auto-remediation (Fix mode)
sudo ./harden.sh --fix
