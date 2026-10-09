# Hardened Linux Audit & Security Baseline

Automated Bash script to audit and harden Debian, Ubuntu, and Linux Mint systems against common security baseline configurations.

## Features Audited
- **SSH Configuration:** Root login policy audit.
- **Kernel Hardening (`sysctl`):** TCP SYN flood protection and ICMP redirect checks.
- **Firewall (`ufw`):** Uncomplicated Firewall active status check.

## Usage

```bash
# Make executable
chmod +x harden.sh

# Run audit (requires root)
sudo ./harden.sh
