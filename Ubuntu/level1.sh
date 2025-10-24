#!/bin/bash

# =============================================================================
# Ubuntu Benchmark Audit Script - Level 1
#
# This script audits a system based on the CIS Level 1 benchmarks.
# It outputs results to both the console (with colors) and a CSV file.
#
# Usage: sudo ./level1.sh
# =============================================================================

# --- Configuration ---
OUTPUT_CSV="csv/audit_report_level1.csv"

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
# --- Helper Functions (similar to level2.sh) ---
# =============================================================================

# Initialize the CSV file with a header
init_csv() {
    echo "ID,Title,Status,Finding" > "$OUTPUT_CSV"
}

# Log a result to the console AND to the CSV file
log_result() {
    local id="$1"
    local title="$2"
    local status="$3"
    local finding="$4"
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
# $1: ID, $2: Title, $3: File Path, $4: Expected Permissions (octal), $5: Expected Owner, $6: Expected Group
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
    local pass=true
    local issues=""

    if [ "$current_perms" != "$perms" ]; then
        pass=false
        issues+="Perms are $current_perms, expected $perms. "
    fi
    if [ "$current_owner" != "$owner" ]; then
        pass=false
        issues+="Owner is $current_owner, expected $owner. "
    fi
    if [ "$current_group" != "$group" ]; then
        pass=false
        issues+="Group is $current_group, expected $group. "
    fi

    if $pass; then
        log_result "$id" "$title" "PASS" "Permissions on '$file' are correctly set to $perms/$owner:$group."
    else
        log_result "$id" "$title" "FAIL" "Incorrect configuration for '$file'. $issues"
    fi
}

# Check mount options on a given mount point
# $1: ID, $2: Title, $3: Mount Point, $4: Option to check (e.g., nodev)
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

# =============================================================================
# --- Audit Check Functions ---
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
check_1_1_19() { check_mount_option "1.1.19" "Ensure noexec option is set on /dev/shm" "/dev/shm" "noexec"; }

check_1_1_16() {
    local id="1.1.16"; local title="Ensure sticky bit is set on all world-writable directories"
    echo -e "\nChecking [$id] $title..."
    local dirs
    dirs=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
    if [ -n "$dirs" ]; then
        log_result "$id" "$title" "FAIL" "Sticky bit not set on world-writable dirs: $dirs"
    else
        log_result "$id" "$title" "PASS" "All world-writable directories have sticky bit set."
    fi
}


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

# --- Section 1.5 - Secure Boot Settings ---
check_1_5_1() {
    local id="1.5.1"; local title="Ensure core dumps are restricted"
    echo -e "\nChecking [$id] $title..."
    local hard_core_limit; hard_core_limit=$(grep -E '^\s*\*\s+hard\s+core' /etc/security/limits.conf /etc/security/limits.d/*)
    local suid_dumpable; suid_dumpable=$(sysctl -n fs.suid_dumpable)
    if [[ "$hard_core_limit" == *"0"* ]] && [ "$suid_dumpable" -eq 0 ]; then
        log_result "$id" "$title" "PASS" "Core dumps are restricted in limits.conf and fs.suid_dumpable is 0."
    else
        log_result "$id" "$title" "FAIL" "Core dump restrictions not fully configured. limits.conf: '$hard_core_limit', fs.suid_dumpable: '$suid_dumpable'."
    fi
}

check_1_5_3() { check_sysctl "1.5.3" "Ensure ASLR is enabled" "kernel.randomize_va_space" "2"; }

# --- Section 1.6 - AppArmor ---
check_1_6_1() { check_pkg_installed "1.6.1" "Ensure AppArmor is installed" "apparmor"; }

check_1_6_2() {
    local id="1.6.2"; local title="Ensure all recommended AppArmor profiles are loaded"
     echo -e "\nChecking [$id] $title..."
     if command -v aa-status &>/dev/null; then
        if aa-status | grep -q "profiles are loaded"; then
             log_result "$id" "$title" "PASS" "AppArmor profiles are loaded."
        else
             log_result "$id" "$title" "FAIL" "AppArmor profiles are not in enforce or complain mode."
        fi
     else
        log_result "$id" "$title" "FAIL" "aa-status command not found."
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
check_2_3_1() { check_pkg_not_installed "2.3.1" "Ensure X Window System is not installed" "xserver-xorg"; }

# =============================================================================
# --- Main Execution ---
# =============================================================================
main() {
    echo "=================================================="
    echo "Starting Ubuntu Benchmark Audit (Level 1)..."
    echo "Results will be saved to: $OUTPUT_CSV"
    echo "=================================================="
    
    init_csv
    
    # Filesystem Configuration
    check_1_1_2
    check_1_1_5
    check_1_1_6
    check_1_1_7
    check_1_1_9
    check_1_1_11
    check_1_1_16
    check_1_1_19

    # Filesystem Integrity
    check_1_3_1
    check_1_3_2
    
    # File Permissions
    check_1_4_1
    check_1_4_2
    check_1_4_3
    check_1_4_4
    check_1_4_9
    
    # Secure Boot Settings
    check_1_5_1
    check_1_5_3

    # AppArmor
    check_1_6_1
    check_1_6_2
    check_1_6_3

    # Services
    check_2_2_1
    check_2_3_1
    
    echo "=================================================="
    echo "Audit Complete. Report saved to $OUTPUT_CSV"
    echo "=================================================="
}

# Run the main function
main
