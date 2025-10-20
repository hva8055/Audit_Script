#!/bin/bash

# ===================================================================================
# Linux Security Benchmark Audit Script (Level 1) with Live Status
#
# Description: This script checks a list of security benchmarks, reports the live
#              status with color-coding in the terminal, and outputs the final
#              results to a clean CSV file.
#
# Usage:       sudo bash benchmark_audit_live.sh > audit_results.csv
#              (You will see the progress in your terminal, and the CSV will be
#              saved to 'audit_results.csv')
# ===================================================================================

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." >&2
   exit 1
fi

# --- Color Definitions for Terminal Output ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# --- Helper Functions ---

# Checks if a given path is a mount point
is_mounted() { findmnt -n "$1" &>/dev/null; }

# Checks if a mount point has a specific option
check_mount_option() {
    local path="$1"
    local option="$2"
    if is_mounted "$path"; then
        findmnt -n -o OPTIONS "$path" | grep -wq "$option"
    else
        return 1
    fi
}

# Checks file permissions and ownership
check_perms() {
    local path="$1"
    local perms="$2"
    local owner_group="$3"
    if [ ! -e "$path" ]; then
        if [[ "$path" == "/etc/at.allow" || "$path" == "/etc/cron.allow" || "$path" == "/etc/anacrontab" ]]; then
            return 0
        else
            return 1
        fi
    fi
    [[ "$(stat -c "%a %U:%G" "$path")" == "$perms $owner_group" ]]
}

# --- Core Check and Reporting Function ---
# Arguments: ID, Title, Profile, Command to execute
run_check() {
-    local id="$1"
    local title="$2"
    local profile="$3"
    local command_to_run="$4"
    local result

    # Print the "currently running" message to the terminal (stderr)
    echo -e " Running: ${id} - ${title}..." >&2

    # Evaluate the command and store its output ("Pass", "Fail", etc.)
    result=$(eval "$command_to_run")

    # Display Pass/Fail/Manual status in the terminal (stderr)
    if [[ "$result" == "Pass" ]]; then
        echo -e "${GREEN}  [PASS]${NC}" >&2
    elif [[ "$result" == "Fail" ]]; then
        echo -e "${RED}  [FAIL]${NC}" >&2
    else # Manual Check
        echo -e "${YELLOW}  [MANUAL]${NC}" >&2
    fi

    # Print the clean CSV line to standard output (for the file)
    echo "$id,\"$title\",$profile,$result"
}


# --- System Detection ---
DISTRO=""
if [ -f /etc/redhat-release ]; then
    DISTRO="RHEL"
elif [ -f /etc/debian_version ]; then
    DISTRO="DEBIAN"
fi

# --- Script Main Body ---

# Print CSV Header to standard output
echo "ID,Title,Profile,Result"
echo "Starting Level 1 Audit..." >&2

# --- 1.1 Initial Setup ---
run_check "1.1.1" "Ensure GPG keys are managed" "L1" 'if [[ "$DISTRO" == "RHEL" ]]; then if ! grep -Psiq "^\s*gpgcheck\s*=\s*0" /etc/yum.conf /etc/yum.repos.d/*.repo; then echo "Pass"; else echo "Fail"; fi; elif [[ "$DISTRO" == "DEBIAN" ]]; then if ! grep -r "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ &>/dev/null; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'
run_check "1.1.2" "Ensure separate partition exists for /tmp" "L1" 'if is_mounted "/tmp"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.5" "Ensure separate partition exists for /var/log/audit" "L1" 'if is_mounted "/var/log/audit"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.6" "Ensure separate partition exists for /home" "L1" 'if is_mounted "/home"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.7" "Ensure nodev option is set for /tmp" "L1" 'if check_mount_option "/tmp" "nodev"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.8" "Ensure nodev option is set for /var/tmp" "L1" 'if check_mount_option "/var/tmp" "nodev"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.9" "Ensure nosuid option is set for /tmp" "L1" 'if check_mount_option "/tmp" "nosuid"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.10" "Ensure nosuid option is set for /var/tmp" "L1" 'if check_mount_option "/var/tmp" "nosuid"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.11" "Ensure noexec option is set for /tmp" "L1" 'if check_mount_option "/tmp" "noexec"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.12" "Ensure noexec option is set for /var/tmp" "L1" 'if check_mount_option "/var/tmp" "noexec"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.13" "Ensure nodev option is set for removable media partitions" "L1" 'echo "Manual Check Required"'
run_check "1.1.14" "Ensure nosuid option is set for removable media partitions" "L1" 'echo "Manual Check Required"'
run_check "1.1.15" "Ensure noexec option is set for removable media partitions" "L1" 'echo "Manual Check Required"'
run_check "1.1.16" "Ensure sticky bit is set on all world-writable directories" "L1" 'if [ -z "$(find / -path /proc -prune -o -path /sys -prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null)" ]; then echo "Pass"; else echo "Fail"; fi'
run_check "1.1.19" "Ensure noexec option is set on /dev/shm" "L1" 'if check_mount_option "/dev/shm" "noexec"; then echo "Pass"; else echo "Fail"; fi'

# --- 1.2 Package Manager Configuration ---
run_check "1.2.1" "Ensure package manager configuration file permissions are correctly set" "L1" 'if [[ "$DISTRO" == "RHEL" ]]; then if check_perms "/etc/yum.conf" "644" "root:root" && ! find /etc/yum.repos.d/ -type f -exec stat -c "%a %U:%G" {} + | grep -qv "644 root:root"; then echo "Pass"; else echo "Fail"; fi; elif [[ "$DISTRO" == "DEBIAN" ]]; then if check_perms "/etc/apt/sources.list" "644" "root:root" && ! find /etc/apt/sources.list.d/ -type f -exec stat -c "%a %U:%G" {} + | grep -qv "644 root:root"; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'
run_check "1.2.2" "Ensure GPG key is configured for package manager" "L1" 'if [[ "$DISTRO" == "RHEL" ]]; then if ! grep -Psiq "^\s*gpgcheck\s*=\s*0" /etc/yum.conf /etc/yum.repos.d/*.repo; then echo "Pass"; else echo "Fail"; fi; elif [[ "$DISTRO" == "DEBIAN" ]]; then if ! grep -r "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ &>/dev/null; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'

# --- 1.3 Filesystem Integrity ---
run_check "1.3.1" "Ensure aide is installed" "L1" 'if command -v aide &>/dev/null; then echo "Pass"; else echo "Fail"; fi'
run_check "1.3.2" "Ensure filesystem integrity is regularly checked" "L1" 'if grep -rhq aide /etc/cron* /var/spool/cron; then echo "Pass"; else echo "Fail"; fi'

# --- 1.4 File Permissions ---
run_check "1.4.1" "Ensure permissions on /etc/shadow are configured" "L1" 'if check_perms "/etc/shadow" "0" "root:shadow"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.2" "Ensure permissions on /etc/gshadow are configured" "L1" 'if check_perms "/etc/gshadow" "0" "root:shadow"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.3" "Ensure permissions on /etc/passwd are configured" "L1" 'if check_perms "/etc/passwd" "644" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.4" "Ensure permissions on /etc/group are configured" "L1" 'if check_perms "/etc/group" "644" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.5" "Ensure permissions on /etc/at.allow are configured" "L1" 'if check_perms "/etc/at.allow" "600" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.6" "Ensure permissions on /etc/cron.allow are configured" "L1" 'if check_perms "/etc/cron.allow" "600" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.7" "Ensure permissions on /etc/crontab are configured" "L1" 'if check_perms "/etc/crontab" "600" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.8" "Ensure permissions on /etc/anacrontab are configured" "L1" 'if check_perms "/etc/anacrontab" "600" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.9" "Ensure permissions on /etc/ssh/sshd_config are configured" "L1" 'if check_perms "/etc/ssh/sshd_config" "600" "root:root"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.4.10" "Ensure access to the su command is restricted" "L1" 'if grep -qE "^\s*auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su; then echo "Pass"; else echo "Fail"; fi'

# --- 1.5 System Hardening ---
run_check "1.5.1" "Ensure core dumps are restricted" "L1" 'if grep -qE "^\s*\*\s+hard\s+core\s+0" /etc/security/limits.conf /etc/security/limits.d/* &>/dev/null && sysctl fs.suid_dumpable | grep -q "fs.suid_dumpable = 0"; then echo "Pass"; else echo "Fail"; fi'
run_check "1.5.3" "Ensure address space layout randomization (ASLR) is enabled" "L1" 'if sysctl kernel.randomize_va_space | grep -q "kernel.randomize_va_space = 2"; then echo "Pass"; else echo "Fail"; fi'

# --- 1.6 AppArmor ---
run_check "1.6.1" "Ensure AppArmor is installed" "L1" 'if [[ "$DISTRO" == "DEBIAN" ]]; then if command -v apparmor_status &>/dev/null; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'
run_check "1.6.2" "Ensure all recommended AppArmor profiles are loaded" "L1" 'if [[ "$DISTRO" == "DEBIAN" ]]; then if command -v apparmor_status &>/dev/null && apparmor_status | grep -q "profiles are in enforce mode"; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'
run_check "1.6.3" "Ensure AppArmor is enabled" "L1" 'if [[ "$DISTRO" == "DEBIAN" ]]; then if systemctl is-enabled --quiet apparmor && systemctl is-active --quiet apparmor; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'

# --- 2 Services ---
run_check "2.1.1" "Ensure unnecessary services are disabled" "L1" 'echo "Manual Check Required"'
run_check "2.2.1" "Ensure time synchronization is in use" "L1" 'if (systemctl is-active --quiet chronyd || systemctl is-active --quiet ntpd || systemctl is-active --quiet systemd-timesyncd) && (systemctl is-enabled --quiet chronyd || systemctl is-enabled --quiet ntpd || systemctl is-enabled --quiet systemd-timesyncd); then echo "Pass"; else echo "Fail"; fi'
run_check "2.3.1" "Ensure X Window System is not installed" "L1" 'if [[ "$DISTRO" == "RHEL" ]]; then if ! rpm -q xorg-x11-server-common &>/dev/null; then echo "Pass"; else echo "Fail"; fi; elif [[ "$DISTRO" == "DEBIAN" ]]; then if ! dpkg -s xserver-xorg-core &>/dev/null; then echo "Pass"; else echo "Fail"; fi; else echo "Not Applicable"; fi'
run_check "2.4.1" "Ensure Avahi Server is not enabled" "L1" 'if ! systemctl is-enabled avahi-daemon &>/dev/null; then echo "Pass"; else echo "Fail"; fi'

echo -e "\n${GREEN}Audit complete. Results saved to your specified file.${NC}" >&2
