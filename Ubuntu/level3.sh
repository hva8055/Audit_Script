#!/bin/bash

# =============================================================================
# Ubuntu Benchmark Audit Script - Level 3 (Combined)
#
# This script merges all Level 1 and Level 2 checks into a single,
# comprehensive audit. It outputs results to both the console (with colors)
# and a CSV file.
#
# Usage: sudo ./level3.sh
# =============================================================================

# --- Configuration ---
OUTPUT_CSV="csv/audit_report_level3.csv"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Root Check ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run this script as root or with sudo.${NC}"
  exit 1
fi

# =============================================================================
# --- Helper Functions (Combined Set) ---
# =============================================================================

# Initialize the CSV file with a header
init_csv() {
    echo "ID,Title,Status,Finding" > "$OUTPUT_CSV"
}

# Log a result to the console AND to the CSV file
log_result() {
    local id="$1"; local title="$2"; local status="$3"; local finding="$4"
    local finding_csv
    
    case "$status" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $finding" ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $finding" ;;
        MANUAL_CHECK_REQUIRED) echo -e "  ${YELLOW}[MANUAL]${NC} $finding" ;;
        INFO) echo -e "  ${YELLOW}[INFO]${NC} $finding" ;;
    esac

    finding_csv=$(echo "$finding" | sed 's/"/""/g')
    echo "\"$id\",\"$title\",\"$status\",\"$finding_csv\"" >> "$OUTPUT_CSV"
}

# Check sysctl values
check_sysctl() {
    local id="$1"; local title="$2"; local param="$3"; local expected="$4"
    local current
    echo -e "\nChecking [$id] $title..."
    if ! current=$(sysctl -n "$param" 2>/dev/null); then
        log_result "$id" "$title" "FAIL" "Sysctl parameter '$param' not found."
        return
    fi
    if [[ "$current" == "$expected" ]]; then
        log_result "$id" "$title" "PASS" "'$param' is set to '$current'."
    else
        log_result "$id" "$title" "FAIL" "'$param' is '$current', expected '$expected'."
    fi
}

# Check if a package is NOT installed
check_pkg_not_installed() {
    local id="$1"; local title="$2"; local pkg="$3"
    echo -e "\nChecking [$id] $title..."
    if dpkg -s "$pkg" &>/dev/null; then
        log_result "$id" "$title" "FAIL" "Package '$pkg' is installed."
    else
        log_result "$id" "$title" "PASS" "Package '$pkg' is not installed."
    fi
}

# Check if a package IS installed
check_pkg_installed() {
    local id="$1"; local title="$2"; local pkg="$3"
    echo -e "\nChecking [$id] $title..."
    if dpkg -s "$pkg" &>/dev/null; then
        log_result "$id" "$title" "PASS" "Package '$pkg' is installed."
    else
        log_result "$id" "$title" "FAIL" "Package '$pkg' is not installed."
    fi
}

# Check file permissions and ownership
check_file_perms() {
    local id="$1"; local title="$2"; local file="$3"; local perms="$4"; local owner="$5"; local group="$6"
    echo -e "\nChecking [$id] $title..."
    if [ ! -e "$file" ]; then
        log_result "$id" "$title" "FAIL" "File '$file' does not exist."
        return
    fi
    local current_perms; current_perms=$(stat -c "%a" "$file")
    local current_owner; current_owner=$(stat -c "%U" "$file")
    local current_group; current_group=$(stat -c "%G" "$file")
    local pass=true; local issues=""

    if [ "$current_perms" != "$perms" ]; then pass=false; issues+="Perms are $current_perms, expected $perms. "; fi
    if [ "$current_owner" != "$owner" ]; then pass=false; issues+="Owner is $current_owner, expected $owner. "; fi
    if [ "$current_group" != "$group" ]; then pass=false; issues+="Group is $current_group, expected $group. "; fi

    if $pass; then
        log_result "$id" "$title" "PASS" "Permissions on '$file' are correct ($perms/$owner:$group)."
    else
        log_result "$id" "$title" "FAIL" "Incorrect configuration for '$file'. $issues"
    fi
}

# Check mount options on a given mount point
check_mount_option() {
    local id="$1"; local title="$2"; local mount_point="$3"; local option="$4"
    echo -e "\nChecking [$id] $title..."
    if ! findmnt --mountpoint "$mount_point" &>/dev/null; then
        log_result "$id" "$title" "FAIL" "'$mount_point' is not a separate mount point."
        return
    fi
    if findmnt -o OPTIONS --target "$mount_point" | grep -q "\b$option\b"; then
        log_result "$id" "$title" "PASS" "'$option' option is set on '$mount_point'."
    else
        log_result "$id" "$title" "FAIL" "'$option' option is NOT set on '$mount_point'."
    fi
}

# Check auditd rules
check_audit_rule() {
    local id="$1"; local title="$2"; local pattern="$3"
    echo -e "\nChecking [$id] $title..."
    if ! command -v auditctl &>/dev/null; then
        log_result "$id" "$title" "FAIL" "auditd package is not installed."
        return
    fi
    if auditctl -l | grep -qE "$pattern"; then
        log_result "$id" "$title" "PASS" "A matching rule is loaded in auditd."
        return
    fi
    if grep -qE "$pattern" /etc/audit/rules.d/*.rules 2>/dev/null; then
        log_result "$id" "$title" "PASS" "A matching rule was found in /etc/audit/rules.d/ (requires restart)."
    else
        log_result "$id" "$title" "FAIL" "No matching audit rule found for '$pattern'."
    fi
}

# =============================================================================
# --- Audit Check Functions (Level 1 & 2) ---
# =============================================================================

# --- Section 1.1 - Filesystem Configuration ---
check_1_1_2() {
    local id="1.1.2"; local title="Ensure separate partition exists for /tmp"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /tmp &>/dev/null; then
        log_result "$id" "$title" "PASS" "/tmp is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/tmp is not on a separate partition."
    fi
}
check_1_1_3() {
    local id="1.1.3"; local title="Ensure separate partition exists for /var"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /var &>/dev/null; then
        log_result "$id" "$title" "PASS" "/var is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/var is not on a separate partition."
    fi
}
check_1_1_4() {
    local id="1.1.4"; local title="Ensure separate partition exists for /var/log"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /var/log &>/dev/null; then
        log_result "$id" "$title" "PASS" "/var/log is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/var/log is not on a separate partition."
    fi
}
check_1_1_5() {
    local id="1.1.5"; local title="Ensure separate partition exists for /var/log/audit"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /var/log/audit &>/dev/null; then
        log_result "$id" "$title" "PASS" "/var/log/audit is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/var/log/audit is not on a separate partition."
    fi
}
check_1_1_6() {
    local id="1.1.6"; local title="Ensure separate partition exists for /home"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /home &>/dev/null; then
        log_result "$id" "$title" "PASS" "/home is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/home is not on a separate partition."
    fi
}
check_1_1_7() { check_mount_option "1.1.7" "Ensure nodev option is set for /tmp" "/tmp" "nodev"; }
check_1_1_9() { check_mount_option "1.1.9" "Ensure nosuid option is set for /tmp" "/tmp" "nosuid"; }
check_1_1_11() { check_mount_option "1.1.11" "Ensure noexec option is set for /tmp" "/tmp" "noexec"; }
check_1_1_16() {
    local id="1.1.16"; local title="Ensure sticky bit is set on all world-writable directories"
    echo -e "\nChecking [$id] $title..."
    local dirs; dirs=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
    if [ -n "$dirs" ]; then
        log_result "$id" "$title" "FAIL" "Sticky bit not set on world-writable dirs: $dirs"
    else
        log_result "$id" "$title" "PASS" "All world-writable directories have sticky bit set."
    fi
}
check_1_1_17() {
    local id="1.1.17"; local title="Ensure user_xattr option is disabled"
    echo -e "\nChecking [$id] $title..."
    local mounts; mounts=$(findmnt -n -o TARGET,OPTIONS | grep -vE '^\s*(/boot|/boot/efi)' | grep 'user_xattr')
    if [ -n "$mounts" ]; then
        log_result "$id" "$title" "FAIL" "'user_xattr' found on: $mounts"
    else
        log_result "$id" "$title" "PASS" "No non-boot partitions found with 'user_xattr'."
    fi
}
check_1_1_18() {
    local id="1.1.18"; local title="Ensure posix_acl option is disabled"
    echo -e "\nChecking [$id] $title..."
    local mounts; mounts=$(findmnt -n -o TARGET,OPTIONS | grep -vE '^\s*(/boot|/boot/efi)' | grep '\bacl\b')
    if [ -n "$mounts" ]; then
        log_result "$id" "$title" "FAIL" "'acl' (posix_acl) found on: $mounts"
    else
        log_result "$id" "$title" "PASS" "No non-boot partitions found with 'acl'."
    fi
}
check_1_1_19() { check_mount_option "1.1.19" "Ensure noexec option is set on /dev/shm" "/dev/shm" "noexec"; }

# --- Section 1.3 - Filesystem Integrity ---
check_1_3_1() { check_pkg_installed "1.3.1" "Ensure AIDE is installed" "aide"; }
check_1_3_2() {
    local id="1.3.2"; local title="Ensure filesystem integrity is regularly checked"
    echo -e "\nChecking [$id] $title..."
    if crontab -l -u root 2>/dev/null | grep -q 'aide' || grep -qr 'aide' /etc/cron.* /etc/crontab; then
        log_result "$id" "$title" "PASS" "Found an 'aide' job in system cron files."
    else
        log_result "$id" "$title" "MANUAL_CHECK_REQUIRED" "Could not find an automated 'aide' cron job. Please verify manually."
    fi
}

# --- Section 1.4 - File Permissions ---
check_1_4_1() { check_file_perms "1.4.1" "Ensure permissions on /etc/shadow are configured" "/etc/shadow" "640" "root" "shadow"; }
check_1_4_2() { check_file_perms "1.4.2" "Ensure permissions on /etc/gshadow are configured" "/etc/gshadow" "640" "root" "shadow"; }
check_1_4_3() { check_file_perms "1.4.3" "Ensure permissions on /etc/passwd are configured" "/etc/passwd" "644" "root" "root"; }
check_1_4_4() { check_file_perms "1.4.4" "Ensure permissions on /etc/group are configured" "/etc/group" "644" "root" "root"; }
check_1_4_9() { check_file_perms "1.4.9" "Ensure permissions on /etc/ssh/sshd_config are configured" "/etc/ssh/sshd_config" "600" "root" "root"; }
check_1_4_10() {
    local id="1.4.10"; local title="Ensure access to the su command is restricted"
    echo -e "\nChecking [$id] $title..."
    local file="/etc/pam.d/su"
    if [ ! -f "$file" ]; then
        log_result "$id" "$title" "FAIL" "File $file not found."
        return
    fi
    if grep -qE '^\s*auth\s+required\s+pam_wheel.so' "$file"; then
        log_result "$id" "$title" "PASS" "'su' access is restricted via pam_wheel in $file."
    else
        log_result "$id" "$title" "FAIL" "pam_wheel.so is not configured in $file."
    fi
}

# --- Section 1.5 - Secure Boot & Kernel Settings ---
check_1_5_1() {
    local id="1.5.1"; local title="Ensure core dumps are restricted"
    echo -e "\nChecking [$id] $title..."
    local hard_core_limit; hard_core_limit=$(grep -E '^\s*\*\s+hard\s+core' /etc/security/limits.conf /etc/security/limits.d/*)
    local suid_dumpable; suid_dumpable=$(sysctl -n fs.suid_dumpable)
    if [[ "$hard_core_limit" == *"0"* ]] && [ "$suid_dumpable" -eq 0 ]; then
        log_result "$id" "$title" "PASS" "Core dumps restricted (limits.conf and fs.suid_dumpable)."
    else
        log_result "$id" "$title" "FAIL" "Core dump restrictions not fully configured."
    fi
}
check_1_5_2() { check_pkg_not_installed "1.5.2" "Ensure prelink is not used" "prelink"; }
check_1_5_3() { check_sysctl "1.5.3" "Ensure ASLR is enabled" "kernel.randomize_va_space" "2"; }

# --- Section 1.6 - AppArmor ---
check_1_6_1() { check_pkg_installed "1.6.1" "Ensure AppArmor is installed" "apparmor"; }
check_1_6_2() {
    local id="1.6.2"; local title="Ensure all recommended AppArmor profiles are loaded"
     echo -e "\nChecking [$id] $title..."
     if command -v aa-status &>/dev/null && aa-status | grep -q "profiles are loaded"; then
        log_result "$id" "$title" "PASS" "AppArmor profiles are loaded."
     else
        log_result "$id" "$title" "FAIL" "AppArmor profiles are not in enforce or complain mode."
     fi
}
check_1_6_3() {
    local id="1.6.3"; local title="Ensure AppArmor is enabled"
    echo -e "\nChecking [$id] $title..."
    if command -v aa-status &>/dev/null && aa-status | grep -q "apparmor module is loaded"; then
        log_result "$id" "$title" "PASS" "AppArmor module is loaded."
    else
        log_result "$id" "$title" "FAIL" "AppArmor module is not loaded."
    fi
}

# --- Section 2 - Services ---
check_2_2_1() {
    local id="2.2.1"; local title="Ensure time synchronization is in use"
    echo -e "\nChecking [$id] $title..."
    if timedatectl status 2>/dev/null | grep -q "NTP service: active"; then
        log_result "$id" "$title" "PASS" "NTP service is active."
    else
        log_result "$id" "$title" "FAIL" "NTP service is not active."
    fi
}
check_2_2_2() {
    local id="2.2.2"; local title="Ensure NTP is configured with authenticated servers"
    echo -e "\nChecking [$id] $title..."
    local conf="/etc/chrony/chrony.conf"
    if [ ! -f "$conf" ]; then
        log_result "$id" "$title" "FAIL" "chrony config $conf not found."
        return
    fi
    local keyfile; keyfile=$(grep -E '^\s*keyfile' "$conf")
    local server_auth; server_auth=$(grep -E '^\s*server.*key\s+' "$conf")
    if [ -n "$keyfile" ] && [ -n "$server_auth" ]; then
        log_result "$id" "$title" "PASS" "chrony is configured with a keyfile and authenticated servers."
    else
        log_result "$id" "$title" "FAIL" "chrony is not configured with authenticated servers."
    fi
}
check_2_2_3() { check_pkg_installed "2.2.3" "Ensure chrony is configured" "chrony"; }
check_2_3_1() { check_pkg_not_installed "2.3.1" "Ensure X Window System is not installed" "xserver-xorg"; }
check_2_4_15() {
    local id="2.4.15"; local title="Ensure IMAP and POP3 services are not enabled"
    echo -e "\nChecking [$id] $title..."
    local ports; ports=$(ss -tlpn | grep -E ':(110|995|143|993)\s')
    if [ -n "$ports" ]; then
        log_result "$id" "$title" "FAIL" "Service found on POP3/IMAP ports: $ports"
    else
        log_result "$id" "$title" "PASS" "No services found on POP3/IMAP ports."
    fi
}
check_2_6_7() {
    local id="2.6.7"; local title="Ensure wireless interfaces are disabled"
    echo -e "\nChecking [$id] $title..."
    if command -v nmcli &>/dev/null; then
        if nmcli radio all | grep -qE '^\s*wifi\s+enabled'; then
            log_result "$id" "$title" "FAIL" "Wireless (wifi) is 'enabled' via NetworkManager."
        else
            log_result "$id" "$title" "PASS" "Wireless (wifi) is 'disabled' via NetworkManager."
        fi
    elif ip link | grep -qE 'wlan[0-9]+|wlp[0-9s]+'; then
        log_result "$id" "$title" "FAIL" "Wireless interfaces found, but nmcli is not."
    else
        log_result "$id" "$title" "PASS" "No nmcli and no wlan*/wlp* interfaces found."
    fi
}

# --- Section 3 - Network Configuration ---
check_3_1_10() { check_sysctl "3.1.10" "Ensure bogus TCP flags are logged" "net.ipv4.conf.all.log_martians" "1"; }
check_3_2_3() { check_sysctl "3.2.3" "Ensure IP Spoofing protection is enabled" "net.ipv4.conf.all.rp_filter" "1"; }
check_3_2_5() { check_sysctl "3.2.5" "Ensure TCP SYN Cookies is enabled" "net.ipv4.tcp_syncookies" "1"; }

# --- Section 4 - Logging and Auditing ---
check_4_1_19() { check_audit_rule "4.1.19" "Ensure unauthorized access attempts are collected" "(-S (open|openat|openbyhandleat)).*(-F exit=-EACCES)"; }
check_4_1_21() { check_audit_rule "4.1.21" "Ensure rename syscall events are collected" "(-S (rename|renameat))"; }
check_4_1_22() { check_audit_rule "4.1.22" "Ensure setxattr syscall events are collected" "(-S (setxattr|lsetxattr|fsetxattr))"; }
check_4_1_23() { check_audit_rule "4.1.23" "Ensure finit_module syscall events are collected" "(-S finit_module)"; }
check_4_1_24() { check_audit_rule "4.1.24" "Ensure delete_module syscall events are collected" "(-S delete_module)"; }
check_4_1_26() { check_audit_rule "4.1.26" "Ensure setuid syscall events are collected" "(-S (setuid|setreuid|setresuid))"; }
check_4_1_27() { check_audit_rule "4.1.27" "Ensure setgid syscall events are collected" "(-S (setgid|setregid|setresgid))"; }
check_4_1_28() {
    local id="4.1.28"; local title="Ensure auditd service is enabled"
    echo -e "\nChecking [$id] $title..."
    if systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd; then
        log_result "$id" "$title" "PASS" "auditd service is active and enabled."
    else
        log_result "$id" "$title" "FAIL" "auditd service is not active or not enabled."
    fi
}
check_4_2_4() {
    local id="4.2.4"; local title="Ensure logs are sent to a remote log host"
    echo -e "\nChecking [$id] $title..."
    if grep -qE '^\s*[^#].*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Remote log host configuration found in rsyslog."
    else
        log_result "$id" "$title" "FAIL" "No remote log host configuration (@host) found."
    fi
}

# --- Section 5 - Access, Authentication and Authorization ---
check_5_1_11() {
    local id="5.1.11"; local title="Ensure non-local interactive users are limited"
    echo -e "\nChecking [$id] $title..."
    local file="/etc/ssh/sshd_config"
    if grep -qE "^\s*(AllowUsers|AllowGroups)" "$file" 2>/dev/null; then
        log_result "$id" "$title" "PASS" "sshd_config contains AllowUsers or AllowGroups."
    else
        log_result "$id" "$title" "FAIL" "sshd_config does not contain AllowUsers or AllowGroups."
    fi
}
check_5_1_12() { check_pkg_installed "5.1.12" "Ensure pam_pkcs11 is configured" "libpam-pkcs11"; }
check_5_4_4() {
    local id="5.4.4"; local title="Ensure sudo uses TTY"
    echo -e "\nChecking [$id] $title..."
    if grep -qrE "^\s*Defaults\s+!requiretty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "FAIL" "Found 'Defaults !requiretty' in sudoers."
    elif grep -qrE "^\s*Defaults\s+requiretty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Found 'Defaults requiretty' in sudoers."
    else
        log_result "$id" "$title" "FAIL" "'Defaults requiretty' is not explicitly set."
    fi
}
check_5_4_5() { log_result "5.4.5" "Ensure sudo file integrity is verified" "MANUAL_CHECK_REQUIRED" "This requires manual verification of custom integrity tools."; }
check_5_4_6() {
    local id="5.4.6"; local title="Ensure sudo logs session traffic"
    echo -e "\nChecking [$id] $title..."
    if grep -qrE "^\s*Defaults\s+(log_input|log_output)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Found 'Defaults log_input' or 'log_output'."
    else
        log_result "$id" "$title" "FAIL" "Sudo 'log_input' or 'log_output' is not configured."
    fi
}
check_5_5_1() {
    local id="5.5.1"; local title="Ensure root login is restricted to console"
    echo -e "\nChecking [$id] $title..."
    if ! grep -qE "^\s*PermitRootLogin\s+no" /etc/ssh/sshd_config 2>/dev/null && [ ! -s /etc/securetty ]; then
        log_result "$id" "$title" "FAIL" "SSH PermitRootLogin not 'no' OR /etc/securetty is empty/missing."
    else
        log_result "$id" "$title" "PASS" "PermitRootLogin is 'no' and /etc/securetty is present."
    fi
}
check_5_7_1() { log_result "5.7.1" "Ensure wireless network access is secured" "MANUAL_CHECK_REQUIRED" "Verify WPA2/WPA3/EAP is in use."; }

# --- Section 6 - System Maintenance ---
check_6_2_2() { check_sysctl "6.2.2" "Ensure dmesg is restricted to root" "kernel.dmesg_restrict" "1"; }
check_6_2_3() { check_sysctl "6.2.3" "Ensure memory space protection is enabled" "kernel.randomize_va_space" "2"; }
check_6_2_5() {
    local id="6.2.5"; local title="Ensure manual updates are controlled"
    echo -e "\nChecking [$id] $title..."
    if dpkg -s unattended-upgrades &>/dev/null; then
        log_result "$id" "$title" "FAIL" "Package 'unattended-upgrades' is installed."
    else
        log_result "$id" "$title" "PASS" "Package 'unattended-upgrades' is not installed."
    fi
}
check_6_4_1() {
    echo -e "\nChecking [6.4.1] Ensure SELinux is installed..."
    log_result "6.4.1" "Ensure SELinux is installed" "INFO" "This is an SELinux check. Ubuntu uses AppArmor by default."
    check_pkg_installed "6.4.1" "(Info) Ensure SELinux is installed" "selinux-utils"
}
check_6_4_2() {
    local id="6.4.2"; local title="Ensure SELinux is enabled"
    echo -e "\nChecking [$id] $title..."
    if ! command -v sestatus &>/dev/null; then
        log_result "$id" "$title" "FAIL" "sestatus command not found (SELinux not installed/enabled)."
        return
    fi
    if sestatus | grep -q "SELinux status:.*enabled"; then
        log_result "$id" "$title" "PASS" "SELinux status is enabled."
    else
        log_result "$id" "$title" "FAIL" "SELinux status is not 'enabled'."
    fi
}
check_6_4_3() {
    local id="6.4.3"; local title="Ensure SELinux is configured in enforcing mode"
    echo -e "\nChecking [$id] $title..."
    if ! command -v sestatus &>/dev/null; then
        log_result "$id" "$title" "FAIL" "sestatus command not found."
        return
    fi
    if sestatus | grep -q "Current mode:.*enforcing"; then
        log_result "$id" "$title" "PASS" "SELinux current mode is 'enforcing'."
    else
        log_result "$id" "$title" "FAIL" "SELinux current mode is not 'enforcing'."
    fi
}
check_6_6_3() { log_result "6.6.3" "Ensure pam_pkcs11 is configured" "MANUAL_CHECK_REQUIRED" "Manual check of /etc/pam_pkcs11/pam_pkcs11.conf is required."; }

# =============================================================================
# --- Main Execution ---
# =============================================================================
main() {
    echo "=================================================="
    echo "Starting Ubuntu Benchmark Audit (Level 3 - Combined)..."
    echo "Results will be saved to: $OUTPUT_CSV"
    echo "=================================================="
    
    init_csv
    
    # --- Section 1 ---
    check_1_1_2;  check_1_1_3;  check_1_1_4;  check_1_1_5;  check_1_1_6;  check_1_1_7
    check_1_1_9;  check_1_1_11; check_1_1_16; check_1_1_17; check_1_1_18; check_1_1_19
    check_1_3_1;  check_1_3_2
    check_1_4_1;  check_1_4_2;  check_1_4_3;  check_1_4_4;  check_1_4_9;  check_1_4_10
    check_1_5_1;  check_1_5_2;  check_1_5_3
    check_1_6_1;  check_1_6_2;  check_1_6_3
    
    # --- Section 2 ---
    check_2_2_1;  check_2_2_2;  check_2_2_3
    check_2_3_1
    check_2_4_15
    check_2_6_7
    
    # --- Section 3 ---
    check_3_1_10; check_3_2_3;  check_3_2_5
    
    # --- Section 4 ---
    check_4_1_19; check_4_1_21; check_4_1_22; check_4_1_23; check_4_1_24; check_4_1_26
    check_4_1_27; check_4_1_28
    check_4_2_4
    
    # --- Section 5 ---
    check_5_1_11; check_5_1_12
    check_5_4_4;  check_5_4_5;  check_5_4_6
    check_5_5_1
    check_5_7_1
    
    # --- Section 6 ---
    check_6_2_2;  check_6_2_3;  check_6_2_5
    check_6_4_1;  check_6_4_2;  check_6_4_3
    check_6_6_3
    
    echo "=================================================="
    echo "Audit Complete. Report saved to $OUTPUT_CSV"
    echo "=================================================="
}

# Run the main function
main
