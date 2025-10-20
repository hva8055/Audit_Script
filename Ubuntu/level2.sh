  #!/bin/bash

# =============================================================================
# Ubuntu Benchmark Audit Script
#
# This script audits a system based on the provided benchmark list.
# It outputs results to both the console (with colors) and a CSV file.
#
# Usage: sudo ./audit.sh
# =============================================================================

# --- Configuration ---
OUTPUT_CSV="audit_report.csv"

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
# --- Helper Functions ---
# =============================================================================

# Initialize the CSV file with a header
init_csv() {
    echo "ID,Title,Status,Finding" > "$OUTPUT_CSV"
}

# Log a result to the console AND to the CSV file
# $1: ID, $2: Title, $3: Status (PASS/FAIL/MANUAL_CHECK_REQUIRED/INFO), $4: Finding
log_result() {
    local id="$1"
    local title="$2"
    local status="$3"
    local finding="$4"
    local finding_csv
    
    # Format for console
    case "$status" in
        PASS)
            echo -e "  ${GREEN}[PASS]${NC} $finding"
            ;;
        FAIL)
            echo -e "  ${RED}[FAIL]${NC} $finding"
            ;;
        MANUAL_CHECK_REQUIRED)
            echo -e "  ${YELLOW}[MANUAL]${NC} $finding"
            ;;
        INFO)
            echo -e "  ${YELLOW}[INFO]${NC} $finding"
            ;;
    esac

    # Format for CSV (escape quotes)
    finding_csv=$(echo "$finding" | sed 's/"/""/g')
    echo "\"$id\",\"$title\",\"$status\",\"$finding_csv\"" >> "$OUTPUT_CSV"
}

# Helper to check sysctl values
# $1: ID, $2: Title, $3: Sysctl Param, $4: Expected Value
check_sysctl() {
    local id="$1"
    local title="$2"
    local param="$3"
    local expected="$4"
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

# Helper to check if a package is NOT installed
# $1: ID, $2: Title, $3: Package Name
check_pkg_not_installed() {
    local id="$1"
    local title="$2"
    local pkg="$3"
    
    echo -e "\nChecking [$id] $title..."
    
    if dpkg -s "$pkg" &>/dev/null; then
        log_result "$id" "$title" "FAIL" "Package '$pkg' is installed."
    else
        log_result "$id" "$title" "PASS" "Package '$pkg' is not installed."
    fi
}

# Helper to check if a package IS installed
# $1: ID, $2: Title, $3: Package Name
check_pkg_installed() {
    local id="$1"
    local title="$2"
    local pkg="$3"
    
    echo -e "\nChecking [$id] $title..."
    
    if dpkg -s "$pkg" &>/dev/null; then
        log_result "$id" "$title" "PASS" "Package '$pkg' is installed."
    else
        log_result "$id" "$title" "FAIL" "Package '$pkg' is not installed."
    fi
}

# Helper to check auditd rules
# $1: ID, $2: Title, $3: Rule Regex Pattern
check_audit_rule() {
    local id="$1"
    local title="$2"
    local pattern="$3"
    
    echo -e "\nChecking [$id] $title..."
    
    if ! command -v auditctl &>/dev/null; then
        log_result "$id" "$title" "FAIL" "auditd package is not installed."
        return
    fi
    
    # Check loaded rules
    if auditctl -l | grep -qE "$pattern"; then
        log_result "$id" "$title" "PASS" "A matching rule is loaded in auditd."
        return
    fi
    
    # Check rule files
    if grep -qE "$pattern" /etc/audit/rules.d/*.rules 2>/dev/null; then
        log_result "$id" "$title" "PASS" "A matching rule was found in /etc/audit/rules.d/ (requires restart)."
    else
        log_result "$id" "$title" "FAIL" "No matching audit rule found for '$pattern'."
    fi
}

# =============================================================================
# --- Audit Check Functions ---
# =============================================================================

check_1_1_3() {
    local id="1.1.3"
    local title="Ensure separate partition exists for /var"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /var &>/dev/null; then
        log_result "$id" "$title" "PASS" "/var is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/var is not on a separate partition."
    fi
}

check_1_1_4() {
    local id="1.1.4"
    local title="Ensure separate partition exists for /var/log"
    echo -e "\nChecking [$id] $title..."
    if findmnt --mountpoint /var/log &>/dev/null; then
        log_result "$id" "$title" "PASS" "/var/log is on a separate partition."
    else
        log_result "$id" "$title" "FAIL" "/var/log is not on a separate partition."
    fi
}

check_1_1_17() {
    local id="1.1.17"
    local title="Ensure the user_xattr mount option is disabled for non-boot partitions"
    echo -e "\nChecking [$id] $title..."
    local mounts
    mounts=$(findmnt -n -o TARGET,OPTIONS | grep -vE '^\s*(/boot|/boot/efi)' | grep 'user_xattr')
    if [ -n "$mounts" ]; then
        log_result "$id" "$title" "FAIL" "'user_xattr' found on: $mounts"
    else
        log_result "$id" "$title" "PASS" "No non-boot partitions found with 'user_xattr'."
    fi
}

check_1_1_18() {
    local id="1.1.18"
    local title="Ensure the posix_acl mount option is disabled for non-boot partitions"
    echo -e "\nChecking [$id] $title..."
    local mounts
    mounts=$(findmnt -n -o TARGET,OPTIONS | grep -vE '^\s*(/boot|/boot/efi)' | grep '\bacl\b')
    if [ -n "$mounts" ]; then
        log_result "$id" "$title" "FAIL" "'acl' (posix_acl) found on: $mounts"
    else
        log_result "$id" "$title" "PASS" "No non-boot partitions found with 'acl'."
    fi
}

check_1_4_10() {
    local id="1.4.10"
    local title="Ensure access to the su command is restricted"
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

check_1_5_2() {
    check_pkg_not_installed "1.5.2" "Ensure prelink is not used" "prelink"
}

check_2_2_2() {
    local id="2.2.2"
    local title="Ensure NTP is configured with authenticated servers"
    echo -e "\nChecking [$id] $title..."
    local conf="/etc/chrony/chrony.conf"
    
    if [ ! -f "$conf" ]; then
        log_result "$id" "$title" "FAIL" "chrony config $conf not found."
        return
    fi
    
    local keyfile
    keyfile=$(grep -E '^\s*keyfile' "$conf")
    local server_auth
    server_auth=$(grep -E '^\s*server.*key\s+' "$conf")
    
    if [ -n "$keyfile" ] && [ -n "$server_auth" ]; then
        log_result "$id" "$title" "PASS" "chrony is configured with a keyfile and authenticated servers."
    else
        log_result "$id" "$title" "FAIL" "chrony is not configured with authenticated servers."
    fi
}

check_2_2_3() {
    check_pkg_installed "2.2.3" "Ensure chrony is configured" "chrony"
}

check_2_4_15() {
    local id="2.4.15"
    local title="Ensure IMAP and POP3 services are not enabled"
    echo -e "\nChecking [$id] $title..."
    local ports
    ports=$(ss -tlpn | grep -E ':(110|995|143|993)\s')
    
    if [ -n "$ports" ]; then
        log_result "$id" "$title" "FAIL" "Service found listening on POP3/IMAP ports: $ports"
    else
        log_result "$id" "$title" "PASS" "No services found listening on POP3/IMAP ports."
    fi
}

check_2_6_7() {
    local id="2.6.7"
    local title="Ensure wireless interfaces are disabled"
    echo -e "\nChecking [$id] $title..."
    if command -v nmcli &>/dev/null; then
        if nmcli radio all | grep -qE '^\s*wifi\s+enabled'; then
            log_result "$id" "$title" "FAIL" "Wireless (wifi) radio is 'enabled' via NetworkManager."
        else
            log_result "$id" "$title" "PASS" "Wireless (wifi) radio is 'disabled' or unavailable via NetworkManager."
        fi
    elif ip link | grep -qE 'wlan[0-9]+|wlp[0-9s]+'; then
        log_result "$id" "$title" "FAIL" "Wireless interfaces (wlan*/wlp*) were found, but nmcli is not."
    else
        log_result "$id" "$title" "PASS" "No nmcli and no wlan*/wlp* interfaces found."
    fi
}

check_3_1_10() {
    check_sysctl "3.1.10" "Ensure bogus TCP flags are logged" "net.ipv4.conf.all.log_martians" "1"
}

check_3_2_3() {
    check_sysctl "3.2.3" "Ensure IP Spoofing protection is enabled" "net.ipv4.conf.all.rp_filter" "1"
}

check_3_2_5() {
    # This benchmark title is vague, but commonly refers to syncookies.
    check_sysctl "3.2.5" "Ensure specific port protection is enabled (syncookies)" "net.ipv4.tcp_syncookies" "1"
}

check_4_1_19() {
    check_audit_rule "4.1.19" "Ensure successful unauthorized access attempts... are collected" "(-S (open|openat|openbyhandleat)).*(-F exit=-EACCES)"
}

check_4_1_21() {
    check_audit_rule "4.1.21" "Ensure events that use the rename syscall are collected" "(-S (rename|renameat))"
}

check_4_1_22() {
    check_audit_rule "4.1.22" "Ensure events that use the setxattr syscall are collected" "(-S (setxattr|lsetxattr|fsetxattr))"
}

check_4_1_23() {
    check_audit_rule "4.1.23" "Ensure events that use the finit_module syscall are collected" "(-S finit_module)"
}

check_4_1_24() {
    check_audit_rule "4.1.24" "Ensure events that use the delete_module syscall are collected" "(-S delete_module)"
}

check_4_1_26() {
    check_audit_rule "4.1.26" "Ensure events that use the setuid syscall are collected" "(-S (setuid|setreuid|setresuid))"
}

check_4_1_27() {
    check_audit_rule "4.1.27" "Ensure events that use the setgid syscall are collected" "(-S (setgid|setregid|setresgid))"
}

check_4_1_28() {
    local id="4.1.28"
    local title="Ensure all events are collected (auditd enabled)"
    echo -e "\nChecking [$id] $title..."
    if systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd; then
        log_result "$id" "$title" "PASS" "auditd service is active and enabled."
    else
        log_result "$id" "$title" "FAIL" "auditd service is not active or not enabled."
    fi
}

check_4_2_4() {
    local id="4.2.4"
    local title="Ensure logs are sent to a remote log host"
    echo -e "\nChecking [$id] $title..."
    if grep -qE '^\s*[^#].*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Remote log host configuration found in rsyslog files."
    else
        log_result "$id" "$title" "FAIL" "No remote log host configuration (@host) found in rsyslog files."
    fi
}

check_5_1_11() {
    local id="5.1.11"
    local title="Ensure non-local interactive users are limited"
    echo -e "\nChecking [$id] $title..."
    local file="/etc/ssh/sshd_config"
    if grep -qE "^\s*(AllowUsers|AllowGroups)" "$file" 2>/dev/null; then
        log_result "$id" "$title" "PASS" "sshd_config contains AllowUsers or AllowGroups."
    else
        log_result "$id" "$title" "FAIL" "sshd_config does not contain AllowUsers or AllowGroups."
    fi
}

check_5_1_12() {
    # 5.1.12 and 6.6.3 appear to be related.
    check_pkg_installed "5.1.12" "Ensure pam_pkcs11 is configured" "libpam-pkcs11"
}

check_5_4_4() {
    local id="5.4.4"
    local title="Ensure sudo is configured to disable the use of non-TTY input"
    echo -e "\nChecking [$id] $title..."
    # 'requiretty' is the default in many sudo versions, but CIS checks for its explicit presence.
    # '!requiretty' is an explicit fail.
    if grep -qrE "^\s*Defaults\s+!requiretty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "FAIL" "Found 'Defaults !requiretty' in sudoers."
    elif grep -qrE "^\s*Defaults\s+requiretty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Found 'Defaults requiretty' in sudoers."
    else
        log_result "$id" "$title" "FAIL" "'Defaults requiretty' is not explicitly set."
    fi
}

check_5_4_5() {
    local id="5.4.5"
    local title="Ensure sudo is configured to verify file integrity"
    echo -e "\nChecking [$id] $title..."
    log_result "$id" "$title" "MANUAL_CHECK_REQUIRED" "This check requires manual verification of custom integrity tools."
}

check_5_4_6() {
    local id="5.4.6"
    local title="Ensure sudo is configured to log session traffic"
    echo -e "\nChecking [$id] $title..."
    if grep -qrE "^\s*Defaults\s+(log_input|log_output)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_result "$id" "$title" "PASS" "Found 'Defaults log_input' or 'log_output' in sudoers."
    else
        log_result "$id" "$title" "FAIL" "Sudo 'log_input' or 'log_output' is not configured."
    fi
}

check_5_5_1() {
    local id="5.5.1"
    local title="Ensure root login is restricted to console"
    echo -e "\nChecking [$id] $title..."
    local ssh_fail=false
    local tty_fail=false
    
    if ! grep -qE "^\s*PermitRootLogin\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        ssh_fail=true
    fi
    
    if [ ! -s /etc/securetty ]; then
        tty_fail=true
    fi
    
    if $ssh_fail || $tty_fail; then
        log_result "$id" "$title" "FAIL" "SSH PermitRootLogin not 'no' (found: $(grep PermitRootLogin /etc/ssh/sshd_config)) OR /etc/securetty is empty/missing."
    else
        log_result "$id" "$title" "PASS" "PermitRootLogin is 'no' and /etc/securetty is present."
    fi
}

check_5_7_1() {
    local id="5.7.1"
    local title="Ensure access to wireless networks is secured"
    echo -e "\nChecking [$id] $title..."
    log_result "$id" "$title" "MANUAL_CHECK_REQUIRED" "Verify WPA2/WPA3/EAP is in use."
}

check_6_2_2() {
    check_sysctl "6.2.2" "Ensure dmesg is restricted to root" "kernel.dmesg_restrict" "1"
}

check_6_2_3() {
    check_sysctl "6.2.3" "Ensure the network stack's memory space is protected" "kernel.randomize_va_space" "2"
}

check_6_2_5() {
    local id="6.2.5"
    local title="Ensure manual updates are controlled"
    echo -e "\nChecking [$id] $title..."
    if dpkg -s unattended-upgrades &>/dev/null; then
        log_result "$id" "$title" "FAIL" "Package 'unattended-upgrades' is installed. Updates may be automatic."
    else
        log_result "$id" "$title" "PASS" "Package 'unattended-upgrades' is not installed."
    fi
}

check_6_2_6() {
    local id="6.2.6"
    local title="Ensure access to wireless networks is secured (Manual)"
    echo -e "\nChecking [$id] $title..."
    log_result "$id" "$title" "MANUAL_CHECK_REQUIRED" "Verify WPA2/WPA3/EAP is in use."
}

check_6_4_1() {
    # Ubuntu uses AppArmor, not SELinux. This check is for SELinux.
    echo -e "\nChecking [6.4.1] Ensure SELinux is installed..."
    log_result "6.4.1" "Ensure SELinux is installed" "INFO" "This is an SELinux check. Ubuntu uses AppArmor by default."
    check_pkg_installed "6.4.1" "Ensure SELinux is installed" "selinux-utils"
}

check_6_4_2() {
    local id="6.4.2"
    local title="Ensure SELinux is enabled"
    echo -e "\nChecking [$id] $title..."
    if ! command -v sestatus &>/dev/null; then
        log_result "$id" "$title" "FAIL" "sestatus command not found. SELinux is not installed/enabled."
        return
    fi
    
    if sestatus | grep -q "SELinux status:.*enabled"; then
        log_result "$id" "$title" "PASS" "SELinux status is enabled."
    else
        log_result "$id" "$title" "FAIL" "SELinux status is not 'enabled'."
    fi
}

check_6_4_3() {
    local id="6.4.3"
    local title="Ensure SELinux is configured"
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

check_6_6_3() {
    local id="6.6.3"
    local title="Ensure pam_pkcs11 is configured (Manual)"
    echo -e "\nChecking [$id] $title..."
    log_result "$id" "$title" "MANUAL_CHECK_REQUIRED" "Manual check of /etc/pam_pkcs11/pam_pkcs11.conf is required."
}

# =============================================================================
# --- Main Execution ---
# =============================================================================
main() {
    echo "=================================================="
    echo "Starting Ubuntu Benchmark Audit..."
    echo "Results will be shown here and saved to: $OUTPUT_CSV"
    echo "=================================================="
    
    init_csv
    
    # Run all checks. Duplicates from your list are ignored.
    check_1_1_3
    check_1_1_4
    check_1_1_17
    check_1_1_18
    check_1_4_10
    check_1_5_2
    check_2_2_2
    check_2_2_3
    check_2_4_15
    check_2_6_7
    check_3_1_10
    check_3_2_3
    check_3_2_5
    check_4_1_19
    check_4_1_21
    check_4_1_22
    check_4_1_23
    check_4_1_24
    check_4_1_26
    check_4_1_27
    check_4_1_28
    check_4_2_4
    check_5_1_11
    check_5_1_12
    check_5_4_4
    check_5_4_5
    check_5_4_6
    check_5_5_1
    check_5_7_1
    check_6_2_2
    check_6_2_3
    check_6_2_5
    check_6_2_6
    check_6_4_1
    check_6_4_2
    check_6_4_3
    check_6_6_3

    echo "=================================================="
    echo "Audit Complete. Report saved to $OUTPUT_CSV"
    echo "=================================================="
}

# Run the main function
main
