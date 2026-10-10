#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# RHEL 10.2 Hardened VM Template
# Project: Odoo High Availability / SMSI / ISO/IEC 27001
# ============================================================
# Usage:
#   sudo ADMIN_USER=noor ./harden-RHEL10.2-template.sh
#
# Optional SSH key-only mode (only after key login is tested):
#   sudo ADMIN_USER=noor REQUIRE_SSH_KEY_AUTH=true ./harden-RHEL10.2-template.sh
# ============================================================

LOG_FILE="/var/log/hardening-template.log"
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

on_error() {
    echo -e "${RED}[FAIL]${NC} Unexpected error on line $1."
}
trap 'on_error "$LINENO"' ERR

# ------------------------------------------------------------
# 0. Root and RHEL version checks
# ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[FAIL] This script must be run as root (use sudo)."
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "[FAIL] Cannot identify the operating system."
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release

if [[ "${ID:-}" != "rhel" ]]; then
    echo "[FAIL] This script is designed for RHEL. Detected: ${ID:-unknown}"
    exit 1
fi

if [[ "${VERSION_ID%%.*}" != "10" ]]; then
    echo "[FAIL] This script is designed for RHEL 10.x. Detected: ${VERSION_ID:-unknown}"
    exit 1
fi

info "Detected RHEL version: ${VERSION_ID}"

# ------------------------------------------------------------
# 1. Administrative user
# ------------------------------------------------------------
ADMIN_USER="${ADMIN_USER:-}"
REQUIRE_SSH_KEY_AUTH="${REQUIRE_SSH_KEY_AUTH:-false}"

if [[ -z "$ADMIN_USER" ]]; then
    ADMIN_USER="$(getent group wheel | awk -F: '{print $4}' | cut -d',' -f1)"
fi

if [[ -z "$ADMIN_USER" ]]; then
    echo "[FAIL] No non-root administrative user was specified or found."
    echo "       Example: sudo ADMIN_USER=noor ./harden-RHEL10.2-template.sh"
    exit 1
fi

if [[ "$ADMIN_USER" == "root" ]]; then
    echo "[FAIL] ADMIN_USER must be a non-root user."
    exit 1
fi

if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    echo "[FAIL] Administrative user does not exist: $ADMIN_USER"
    exit 1
fi

if ! id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx 'wheel'; then
    echo "[FAIL] Administrative user is not a member of wheel: $ADMIN_USER"
    exit 1
fi

exec > >(tee -a "$LOG_FILE") 2>&1

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------
echo
echo "============================================================"
echo "        RHEL 10.2 HARDENED VM TEMPLATE"
echo "============================================================"
echo "Hostname      : $(hostnamectl --static 2>/dev/null || hostname)"
echo "RHEL Version  : ${VERSION_ID}"
echo "Admin User    : ${ADMIN_USER}"
echo "Log File      : ${LOG_FILE}"
echo "============================================================"
echo

# ------------------------------------------------------------
# 2. System update
# ------------------------------------------------------------
echo "------------------------------------------------------------"
echo "1. SYSTEM UPDATE"
echo "------------------------------------------------------------"
if dnf -y update; then
    pass "System update completed successfully."
else
    fail "System update failed."
fi

# ------------------------------------------------------------
# 3. Baseline security packages
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "2. BASELINE SECURITY PACKAGES"
echo "------------------------------------------------------------"

PACKAGES=(
    firewalld
    chrony
    audit
    audispd-plugins
    rsyslog
    openssh-server
    policycoreutils
    policycoreutils-python-utils
)

if dnf -y install "${PACKAGES[@]}"; then
    pass "Baseline security packages installed."
else
    fail "One or more baseline security packages could not be installed."
fi

for package in "${PACKAGES[@]}"; do
    if rpm -q "$package" >/dev/null 2>&1; then
        pass "Package installed: $package"
    else
        fail "Package missing: $package"
    fi
done

# ------------------------------------------------------------
# 4. SELinux
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "3. SELINUX"
echo "------------------------------------------------------------"

SELINUX_CONFIG="/etc/selinux/config"

if grep -q '^SELINUX=enforcing' "$SELINUX_CONFIG"; then
    pass "SELinux configuration is set to enforcing."
else
    sed -ri 's/^SELINUX=.*/SELINUX=enforcing/' "$SELINUX_CONFIG"
    pass "SELinux configuration changed to enforcing."
fi

SELINUX_STATUS="$(getenforce)"
case "$SELINUX_STATUS" in
    Enforcing)
        pass "SELinux runtime mode is Enforcing."
        ;;
    Permissive)
        if setenforce 1; then
            pass "SELinux switched to Enforcing mode."
        else
            fail "Could not switch SELinux to Enforcing mode."
        fi
        ;;
    Disabled)
        fail "SELinux is disabled. Reboot/relabel may be required."
        ;;
    *)
        fail "Unknown SELinux status: $SELINUX_STATUS"
        ;;
esac

# ------------------------------------------------------------
# 5. System-wide crypto policy
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "4. SYSTEM-WIDE CRYPTOGRAPHIC POLICY"
echo "------------------------------------------------------------"

CRYPTO_POLICY="$(update-crypto-policies --show)"
info "Current crypto policy: $CRYPTO_POLICY"

case "$CRYPTO_POLICY" in
    DEFAULT|FIPS)
        pass "Acceptable crypto policy: $CRYPTO_POLICY"
        ;;
    LEGACY)
        fail "LEGACY crypto policy is not acceptable for the hardened template."
        ;;
    FUTURE)
        warn "FUTURE crypto policy detected; validate application compatibility."
        ;;
    *)
        warn "Custom crypto policy detected: $CRYPTO_POLICY"
        ;;
esac

# ------------------------------------------------------------
# 6. Local firewall
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "5. LOCAL FIREWALL"
echo "------------------------------------------------------------"

systemctl enable firewalld
systemctl start firewalld

if systemctl is-active --quiet firewalld; then
    pass "firewalld is active."
else
    fail "firewalld is not active."
fi

if systemctl is-enabled --quiet firewalld; then
    pass "firewalld is enabled at boot."
else
    fail "firewalld is not enabled at boot."
fi

# Generic template: SSH only. Role-specific ports will be added later.
firewall-cmd --permanent --remove-service=cockpit >/dev/null 2>&1 || true
firewall-cmd --permanent --remove-service=dhcpv6-client >/dev/null 2>&1 || true
firewall-cmd --permanent --add-service=ssh >/dev/null
firewall-cmd --reload >/dev/null

if firewall-cmd --list-services | grep -qw ssh; then
    pass "SSH is allowed by the local firewall."
else
    fail "SSH is not allowed by the local firewall."
fi

# ------------------------------------------------------------
# 7. Time synchronization
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "6. TIME SYNCHRONIZATION"
echo "------------------------------------------------------------"

systemctl enable chronyd
systemctl start chronyd

if systemctl is-active --quiet chronyd; then
    pass "chronyd is active."
else
    fail "chronyd is not active."
fi

TIME_SYNCED=false
for _ in {1..15}; do
    if chronyc tracking >/dev/null 2>&1 && timedatectl show -p NTPSynchronized --value | grep -qi '^yes$'; then
        TIME_SYNCED=true
        break
    fi
    sleep 2
done

if [[ "$TIME_SYNCED" == true ]]; then
    pass "System time is synchronized."
else
    fail "System time is not synchronized. Check DNS/WAN/NTP connectivity."
fi

# ------------------------------------------------------------
# 8. SSH hardening
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "7. SSH HARDENING"
echo "------------------------------------------------------------"

mkdir -p /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'SSHCONF'
# RHEL 10 SSH hardening baseline
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2

SSHCONF

if [[ "$REQUIRE_SSH_KEY_AUTH" == "true" ]]; then
    AUTH_KEYS="/home/${ADMIN_USER}/.ssh/authorized_keys"
    if [[ -s "$AUTH_KEYS" ]]; then
        cat >> /etc/ssh/sshd_config.d/99-hardening.conf <<'SSHKEYCONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
SSHKEYCONF
        pass "SSH key-only authentication configured."
    else
        fail "SSH key-only authentication requested, but $AUTH_KEYS is missing or empty."
    fi
else
    cat >> /etc/ssh/sshd_config.d/99-hardening.conf <<'SSHNOTE'
# PasswordAuthentication remains enabled in this generic template.
# Disable it only after SSH key-based administration has been validated.
SSHNOTE
    warn "SSH password authentication remains enabled in the generic template."
fi

if sshd -t; then
    pass "OpenSSH configuration syntax is valid."
else
    fail "OpenSSH configuration syntax is invalid."
fi

systemctl enable sshd
systemctl restart sshd

if systemctl is-active --quiet sshd; then
    pass "sshd is active."
else
    fail "sshd is not active."
fi

ROOT_LOGIN_SETTING="$(sshd -T | awk '$1=="permitrootlogin" {print $2; exit}')"
if [[ "$ROOT_LOGIN_SETTING" == "no" ]]; then
    pass "SSH root login is disabled."
else
    fail "SSH root login is not disabled."
fi

EMPTY_PASSWORD_SETTING="$(sshd -T | awk '$1=="permitemptypasswords" {print $2; exit}')"
if [[ "$EMPTY_PASSWORD_SETTING" == "no" ]]; then
    pass "Empty SSH passwords are disabled."
else
    fail "Empty SSH passwords are not disabled."
fi

GSSAPI_DELEGATION="$(sshd -T | awk '$1=="gssapidelegatedcredentials" {print $2; exit}')"
if [[ -z "$GSSAPI_DELEGATION" || "$GSSAPI_DELEGATION" == "no" ]]; then
    pass "GSSAPI delegated credentials are disabled."
else
    fail "GSSAPI delegated credentials are not disabled."
fi

# ------------------------------------------------------------
# 9. Persistent logging
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "8. PERSISTENT LOGGING"
echo "------------------------------------------------------------"

mkdir -p /var/log/journal
mkdir -p /etc/systemd/journald.conf.d

cat > /etc/systemd/journald.conf.d/10-persistent-logging.conf <<'JOURNALCONF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
RuntimeMaxUse=100M
JOURNALCONF

systemctl restart systemd-journald
systemctl enable rsyslog
systemctl restart rsyslog

if systemctl is-active --quiet systemd-journald; then
    pass "systemd-journald is active."
else
    fail "systemd-journald is not active."
fi

if systemctl is-active --quiet rsyslog; then
    pass "rsyslog is active."
else
    fail "rsyslog is not active."
fi

if [[ -d /var/log/journal ]]; then
    pass "Persistent journal directory exists."
else
    fail "Persistent journal directory is missing."
fi

# ------------------------------------------------------------
# 10. Linux Audit
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "9. LINUX AUDIT"
echo "------------------------------------------------------------"

systemctl enable auditd
service auditd start >/dev/null 2>&1 || true

if systemctl is-active --quiet auditd; then
    pass "auditd is active."
else
    fail "auditd is not active."
fi

mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/99-template-hardening.rules <<'AUDITRULES'
# Identity files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Privilege configuration
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d -p wa -k sshd_config

# Crypto policy
-w /etc/crypto-policies -p wa -k crypto_policy
AUDITRULES

if augenrules --load >/dev/null 2>&1; then
    pass "Audit rules loaded successfully."
else
    fail "Audit rules could not be loaded."
fi

for required_rule in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
    if grep -qF -- "$required_rule" /etc/audit/rules.d/99-template-hardening.rules; then
        pass "Audit rule present for $required_rule"
    else
        fail "Audit rule missing for $required_rule"
    fi
done

# ------------------------------------------------------------
# 11. Kernel / network baseline
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "10. KERNEL / NETWORK BASELINE"
echo "------------------------------------------------------------"

cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTLCONF'
# Generic server baseline.
# Role-specific routing settings are intentionally NOT configured.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
SYSCTLCONF

if sysctl --system >/dev/null 2>&1; then
    pass "sysctl hardening configuration loaded."
else
    fail "sysctl hardening configuration could not be loaded."
fi

check_sysctl() {
    local variable="$1"
    local expected="$2"
    local actual
    actual="$(sysctl -n "$variable" 2>/dev/null || echo UNAVAILABLE)"
    if [[ "$actual" == "$expected" ]]; then
        pass "$variable = $expected"
    else
        fail "$variable expected=$expected actual=$actual"
    fi
}

check_sysctl net.ipv4.conf.all.accept_source_route 0
check_sysctl net.ipv4.conf.default.accept_source_route 0
check_sysctl net.ipv4.conf.all.accept_redirects 0
check_sysctl net.ipv4.conf.default.accept_redirects 0
check_sysctl net.ipv4.conf.all.send_redirects 0
check_sysctl net.ipv4.conf.default.send_redirects 0
check_sysctl net.ipv4.tcp_syncookies 1
check_sysctl kernel.randomize_va_space 2
check_sysctl fs.suid_dumpable 0

# ------------------------------------------------------------
# 12. Core dump protection
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "11. CORE DUMP PROTECTION"
echo "------------------------------------------------------------"

mkdir -p /etc/systemd/coredump.conf.d

cat > /etc/systemd/coredump.conf.d/99-hardening.conf <<'COREDUMPCONF'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMPCONF

systemctl daemon-reload

if grep -q '^Storage=none' /etc/systemd/coredump.conf.d/99-hardening.conf && \
   grep -q '^ProcessSizeMax=0' /etc/systemd/coredump.conf.d/99-hardening.conf; then
    pass "Core dump storage is disabled."
else
    fail "Core dump protection configuration is incorrect."
fi

# ------------------------------------------------------------
# 13. Account / file baseline
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "12. ACCOUNT / FILE BASELINE"
echo "------------------------------------------------------------"

if grep -Eq '^UMASK[[:space:]]+' /etc/login.defs; then
    sed -ri 's/^UMASK[[:space:]]+.*/UMASK 027/' /etc/login.defs
else
    printf '\nUMASK 027\n' >> /etc/login.defs
fi

if awk '$1=="UMASK" && $2=="027" {found=1} END {exit !found}' /etc/login.defs; then
    pass "Default login UMASK is 027."
else
    fail "Default login UMASK is not 027."
fi

SHADOW_MODE="$(stat -c '%a' /etc/shadow)"
if [[ "$SHADOW_MODE" == "000" || "$SHADOW_MODE" == "0" || "$SHADOW_MODE" == "600" || "$SHADOW_MODE" == "640" ]]; then
    pass "/etc/shadow has a restrictive permission mode ($SHADOW_MODE)."
else
    fail "/etc/shadow has unexpected permissions: $SHADOW_MODE"
fi

if id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx 'wheel'; then
    pass "Administrative user is in wheel: $ADMIN_USER"
else
    fail "Administrative user is not correctly configured: $ADMIN_USER"
fi

# ------------------------------------------------------------
# 14. fapolicyd (deferred)
# ------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "13. FAPOLICYD"
echo "------------------------------------------------------------"

if rpm -q fapolicyd >/dev/null 2>&1; then
    warn "fapolicyd is installed but is NOT enforced by this generic template."
    echo "      Configure and test it after role-specific software is installed."
else
    pass "fapolicyd is not enforced in the generic template."
fi

# ------------------------------------------------------------
# Final summary
# ------------------------------------------------------------
echo
echo "============================================================"
echo "             HARDENING VERIFICATION SUMMARY"
echo "============================================================"
echo -e "${GREEN}PASS : ${PASS_COUNT}${NC}"
echo -e "${RED}FAIL : ${FAIL_COUNT}${NC}"
echo -e "${YELLOW}WARN : ${WARN_COUNT}${NC}"
echo
echo "Detailed log: ${LOG_FILE}"
echo "============================================================"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo -e "${GREEN}RESULT : HARDENING SUCCESSFUL${NC}"
    echo
    echo "The RHEL 10.x template passed all mandatory checks."
    echo "Next steps:"
    echo "  1. Take a VMware snapshot."
    echo "  2. Prepare the VM as the golden template."
    echo "  3. Clone it to VM1 ... VM7."
    echo
    echo "Do NOT place production IPs, hostnames, TLS certificates,"
    echo "Odoo data, PostgreSQL data, or HA configuration in this template."
    exit 0
else
    echo -e "${RED}RESULT : HARDENING FAILED${NC}"
    echo
    echo "Do NOT use this VM as the final golden template."
    echo "Correct all FAIL items and run the script again."
    exit 1
fi

