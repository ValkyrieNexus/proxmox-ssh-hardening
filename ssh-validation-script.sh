#!/usr/bin/env bash
# SSH Hardening Validation Script
# Tests the hardened SSH configuration
# v2.0

set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
echo_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

get_current_ssh_port() {
  grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22"
}

get_current_allow_users() {
  grep -E "^AllowUsers\s+" /etc/ssh/sshd_config 2>/dev/null | sed 's/^AllowUsers\s*//' || echo ""
}

detect_ssh_service() {
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    echo sshd
  else
    echo ssh
  fi
}

# Test functions
test_ssh_config() {
    echo_info "Testing SSH configuration syntax..."
    
    if sshd -t 2>/dev/null; then
        echo_pass "SSH configuration syntax is valid"
        return 0
    else
        echo_fail "SSH configuration has syntax errors"
        echo "       Run 'sudo sshd -t' for details"
        return 1
    fi
}

test_ssh_service() {
    local ssh_service=$(detect_ssh_service)
    echo_info "Testing SSH service status..."
    
    if systemctl is-active "$ssh_service" >/dev/null 2>&1; then
        echo_pass "SSH service ($ssh_service) is running"
        return 0
    else
        echo_fail "SSH service ($ssh_service) is not running"
        echo "       Run 'sudo systemctl status $ssh_service' for details"
        return 1
    fi
}

test_ssh_port() {
    local port=$1
    echo_info "Testing SSH port $port..."
    
    # Test with netstat
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tlnp 2>/dev/null | grep ":${port} " | grep -q sshd; then
            echo_pass "SSH is listening on port $port (netstat)"
            return 0
        fi
    fi
    
    # Test with ss
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep ":${port} " | grep -q sshd; then
            echo_pass "SSH is listening on port $port (ss)"
            return 0
        fi
    fi
    
    # Test with lsof
    if command -v lsof >/dev/null 2>&1; then
        if lsof -i -P -n 2>/dev/null | grep "sshd.*:${port} "; then
            echo_pass "SSH is listening on port $port (lsof)"
            return 0
        fi
    fi
    
    echo_fail "SSH is not listening on port $port"
    echo "       Available tools tested: netstat, ss, lsof"
    return 1
}

test_root_login_disabled() {
    echo_info "Testing root login restriction..."
    
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        echo_pass "Root login is disabled"
        return 0
    else
        local root_setting=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "not set")
        echo_fail "Root login may still be enabled"
        echo "       Current setting: $root_setting"
        return 1
    fi
}

test_password_auth_disabled() {
    echo_info "Testing password authentication..."
    
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        echo_pass "Password authentication is disabled"
        return 0
    else
        local pass_setting=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "not set")
        echo_fail "Password authentication may still be enabled"
        echo "       Current setting: $pass_setting"
        return 1
    fi
}

test_pubkey_auth_enabled() {
    echo_info "Testing public key authentication..."
    
    if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        echo_pass "Public key authentication is enabled"
        return 0
    else
        local pubkey_setting=$(grep "^PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "not set (usually defaults to yes)")
        echo_warn "Public key authentication setting not explicitly found"
        echo "       Current setting: $pubkey_setting"
        return 1
    fi
}

test_user_restrictions() {
    local admin_user=$1
    echo_info "Testing user access restrictions..."
    
    local allow_users=$(get_current_allow_users)
    if [[ -n "$allow_users" ]]; then
        echo_pass "User access is restricted"
        echo "       AllowUsers: $allow_users"
        
        # Check if the expected user is in the list
        if [[ -n "$admin_user" ]] && echo "$allow_users" | grep -q "$admin_user"; then
            echo_pass "Expected user '$admin_user' is in AllowUsers"
        elif [[ -n "$admin_user" ]]; then
            echo_warn "Expected user '$admin_user' not found in AllowUsers"
        fi
        return 0
    else
        echo_warn "No AllowUsers directive found - all users may be allowed"
        return 1
    fi
}

test_security_settings() {
    echo_info "Testing additional security settings..."
    
    local passed=0
    local total=0
    
    # Test MaxAuthTries
    ((total++))
    local max_auth=$(grep "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ -n "$max_auth" ]] && [[ "$max_auth" -le 5 ]]; then
        echo_pass "MaxAuthTries is set to $max_auth (secure)"
        ((passed++))
    else
        echo_warn "MaxAuthTries not set or too high: ${max_auth:-default}"
    fi
    
    # Test X11Forwarding
    ((total++))
    if grep -q "^X11Forwarding no" /etc/ssh/sshd_config 2>/dev/null; then
        echo_pass "X11Forwarding is disabled"
        ((passed++))
    else
        echo_warn "X11Forwarding may be enabled"
    fi
    
    # Test AllowAgentForwarding
    ((total++))
    if grep -q "^AllowAgentForwarding no" /etc/ssh/sshd_config 2>/dev/null; then
        echo_pass "Agent forwarding is disabled"
        ((passed++))
    else
        echo_warn "Agent forwarding setting not found"
    fi
    
    # Test ClientAliveInterval
    ((total++))
    local alive_interval=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ -n "$alive_interval" ]] && [[ "$alive_interval" -gt 0 ]]; then
        echo_pass "ClientAliveInterval is set to $alive_interval seconds"
        ((passed++))
    else
        echo_warn "ClientAliveInterval not set"
    fi
    
    return $((total - passed))
}

test_socket_activation() {
    echo_info "Testing SSH socket activation..."
    
    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
        if systemctl is-active ssh.socket >/dev/null 2>&1; then
            echo_warn "SSH socket activation is enabled and active"
            echo "       This may interfere with custom port configurations"
            return 1
        else
            echo_info "SSH socket is enabled but not active"
            return 0
        fi
    else
        echo_pass "SSH socket activation is disabled"
        return 0
    fi
}

test_key_files() {
    local keys_dir=$1
    local admin_user=$2
    echo_info "Testing generated key files..."
    
    if [[ -z "$keys_dir" ]] || [[ ! -d "$keys_dir" ]]; then
        echo_warn "No keys directory specified or found"
        return 1
    fi
    
    local errors=0
    
    # Test Ed25519 keys
    if [[ -f "${keys_dir}/${admin_user}_ed25519" ]]; then
        echo_pass "Ed25519 private key exists"
        if [[ $(stat -c %a "${keys_dir}/${admin_user}_ed25519" 2>/dev/null) == "600" ]]; then
            echo_pass "Ed25519 private key has correct permissions (600)"
        else
            echo_fail "Ed25519 private key has incorrect permissions"
            ((errors++))
        fi
    else
        echo_info "Ed25519 private key not found (optional)"
    fi
    
    if [[ -f "${keys_dir}/${admin_user}_ed25519.pub" ]]; then
        echo_pass "Ed25519 public key exists"
    fi
    
    # Test RSA keys
    if [[ -f "${keys_dir}/${admin_user}_rsa4096" ]]; then
        echo_pass "RSA-4096 private key exists"
        if [[ $(stat -c %a "${keys_dir}/${admin_user}_rsa4096" 2>/dev/null) == "600" ]]; then
            echo_pass "RSA-4096 private key has correct permissions (600)"
        else
            echo_fail "RSA-4096 private key has incorrect permissions"
            ((errors++))
        fi
    else
        echo_info "RSA-4096 private key not found (optional)"
    fi
    
    return $errors
}

test_authorized_keys() {
    local admin_user=$1
    echo_info "Testing authorized_keys setup..."
    
    local auth_keys="/home/${admin_user}/.ssh/authorized_keys"
    
    if [[ ! -d "/home/${admin_user}" ]]; then
        echo_warn "User home directory not found: /home/${admin_user}"
        return 1
    fi
    
    if [[ -f "$auth_keys" ]]; then
        echo_pass "authorized_keys file exists"
        
        # Check permissions
        local perms=$(stat -c %a "$auth_keys" 2>/dev/null)
        if [[ "$perms" == "600" ]]; then
            echo_pass "authorized_keys has correct permissions (600)"
        else
            echo_fail "authorized_keys has incorrect permissions: $perms"
            return 1
        fi
        
        # Check ownership
        local owner=$(stat -c %U "$auth_keys" 2>/dev/null)
        if [[ "$owner" == "$admin_user" ]]; then
            echo_pass "authorized_keys has correct ownership"
        else
            echo_fail "authorized_keys has incorrect ownership: $owner"
            return 1
        fi
        
        # Check content
        local key_count=$(wc -l < "$auth_keys" 2>/dev/null)
        echo_pass "authorized_keys contains $key_count key(s)"
        
    else
        echo_warn "authorized_keys file not found: $auth_keys"
        return 1
    fi
    
    return 0
}

# Main validation
main() {
    echo "SSH Hardening Validation Script v2.0"
    echo "===================================="
    echo
    
    # Get parameters
    local admin_user=${1:-}
    local ssh_port=${2:-}
    local keys_dir=${3:-}
    
    # Auto-detect current SSH port
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(get_current_ssh_port)
        echo_info "Auto-detected SSH port: $ssh_port"
    fi
    
    # Auto-detect admin user from AllowUsers
    if [[ -z "$admin_user" ]]; then
        local allow_users=$(get_current_allow_users)
        if [[ -n "$allow_users" ]]; then
            admin_user=$(echo "$allow_users" | awk '{print $1}' | cut -d'@' -f1)
            echo_info "Auto-detected admin user: $admin_user"
        fi
    fi
    
    # Auto-detect keys directory
    if [[ -z "$keys_dir" ]] && [[ -n "$admin_user" ]]; then
        keys_dir=$(find /root -maxdepth 1 -name "ssh-generated-keys-*" -type d | sort | tail -1)
        if [[ -n "$keys_dir" ]]; then
            echo_info "Auto-detected keys directory: $keys_dir"
        fi
    fi
    
    echo
    echo "Configuration Summary:"
    echo "====================="
    echo "SSH Port: $ssh_port"
    echo "Admin User: ${admin_user:-unknown}"
    echo "Keys Directory: ${keys_dir:-not found}"
    echo "AllowUsers: $(get_current_allow_users || echo 'not set')"
    echo
    
    local tests_passed=0
    local tests_total=0
    
    # Core functionality tests
    ((tests_total++)); test_ssh_config && ((tests_passed++))
    ((tests_total++)); test_ssh_service && ((tests_passed++))
    ((tests_total++)); test_ssh_port "$ssh_port" && ((tests_passed++))
    
    # Security configuration tests
    ((tests_total++)); test_root_login_disabled && ((tests_passed++))
    ((tests_total++)); test_password_auth_disabled && ((tests_passed++))
    ((tests_total++)); test_pubkey_auth_enabled && ((tests_passed++))
    
    # User and access tests
    if [[ -n "$admin_user" ]]; then
        ((tests_total++)); test_user_restrictions "$admin_user" && ((tests_passed++))
        ((tests_total++)); test_authorized_keys "$admin_user" && ((tests_passed++))
    fi
    
    # Additional security tests
    ((tests_total++)); test_security_settings && ((tests_passed++))
    ((tests_total++)); test_socket_activation && ((tests_passed++))
    
    # Key file tests
    if [[ -n "$keys_dir" ]] && [[ -n "$admin_user" ]]; then
        ((tests_total++)); test_key_files "$keys_dir" "$admin_user" && ((tests_passed++))
    fi
    
    # Summary
    echo
    echo "Validation Summary"
    echo "=================="
    echo "Tests passed: $tests_passed/$tests_total"
    echo
    
    if [[ $tests_passed -eq $tests_total ]]; then
        echo_pass "All tests passed! SSH hardening appears successful."
        echo
        echo "Connection Test:"
        if [[ -n "$admin_user" ]] && [[ -n "$keys_dir" ]] && [[ -f "${keys_dir}/${admin_user}_ed25519" ]]; then
            echo "ssh -i ${keys_dir}/${admin_user}_ed25519 -p $ssh_port $admin_user@$(hostname -I | awk '{print $1}' 2>/dev/null || echo 'your-server-ip')"
        else
            echo "ssh -p $ssh_port ${admin_user:-username}@$(hostname -I | awk '{print $1}' 2>/dev/null || echo 'your-server-ip')"
        fi
        return 0
    else
        local failed=$((tests_total - tests_passed))
        echo_warn "$failed test(s) failed. Please review the configuration."
        echo
        echo "Common fixes:"
        echo "- Run: sudo systemctl restart ssh"
        echo "- Check: sudo sshd -t"
        echo "- View logs: sudo journalctl -u ssh -f"
        return 1
    fi
}

# Usage information
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "SSH Hardening Validation Script v2.0"
    echo "===================================="
    echo
    echo "Usage: $0 [admin_user] [ssh_port] [keys_directory]"
    echo
    echo "Parameters (all optional - will auto-detect if not provided):"
    echo "  admin_user      - Admin username to validate"
    echo "  ssh_port        - SSH port number to test"
    echo "  keys_directory  - Path to generated SSH keys"
    echo
    echo "Examples:"
    echo "  $0                              # Auto-detect all parameters"
    echo "  $0 admin                        # Specify user, auto-detect rest"
    echo "  $0 admin 2222                   # Specify user and port"
    echo "  $0 admin 2222 /root/keys        # Specify all parameters"
    echo
    exit 0
fi

# Run validation
main "$@"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
echo_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Test functions
test_ssh_config() {
    echo_info "Testing SSH configuration..."
    
    if sshd -t 2>/dev/null; then
        echo_pass "SSH configuration syntax is valid"
        return 0
    else
        echo_fail "SSH configuration has syntax errors"
        return 1
    fi
}

test_ssh_service() {
    echo_info "Testing SSH service status..."
    
    if systemctl is-active ssh >/dev/null 2>&1; then
        echo_pass "SSH service is running"
        return 0
    elif systemctl is-active sshd >/dev/null 2>&1; then
        echo_pass "SSH service is running"
        return 0
    else
        echo_fail "SSH service is not running"
        return 1
    fi
}

test_ssh_port() {
    local port=$1
    echo_info "Testing SSH port $port..."
    
    if netstat -tlnp | grep ":${port} " | grep sshd >/dev/null 2>&1; then
        echo_pass "SSH is listening on port $port"
        return 0
    elif ss -tlnp | grep ":${port} " | grep sshd >/dev/null 2>&1; then
        echo_pass "SSH is listening on port $port"
        return 0
    else
        echo_fail "SSH is not listening on port $port"
        return 1
    fi
}

test_root_login_disabled() {
    echo_info "Testing root login restriction..."
    
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo_pass "Root login is disabled"
        return 0
    else
        echo_fail "Root login may still be enabled"
        return 1
    fi
}

test_password_auth_disabled() {
    echo_info "Testing password authentication..."
    
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo_pass "Password authentication is disabled"
        return 0
    else
        echo_fail "Password authentication may still be enabled"
        return 1
    fi
}

test_pubkey_auth_enabled() {
    echo_info "Testing public key authentication..."
    
    if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config; then
        echo_pass "Public key authentication is enabled"
        return 0
    else
        echo_warn "Public key authentication setting not explicitly found"
        return 1
    fi
}

test_user_restrictions() {
    local admin_user=$1
    echo_info "Testing user access restrictions..."
    
    if grep -q "^AllowUsers.*${admin_user}" /etc/ssh/sshd_config; then
        echo_pass "User access is restricted to specified users"
        return 0
    else
        echo_warn "AllowUsers directive not found - all users may be allowed"
        return 1
    fi
}

test_key_files() {
    local keys_dir=$1
    local admin_user=$2
    echo_info "Testing generated key files..."
    
    local errors=0
    
    if [[ -f "${keys_dir}/${admin_user}_ed25519" ]]; then
        echo_pass "Ed25519 private key exists"
        if [[ $(stat -c %a "${keys_dir}/${admin_user}_ed25519") == "600" ]]; then
            echo_pass "Ed25519 private key has correct permissions (600)"
        else
            echo_fail "Ed25519 private key has incorrect permissions"
            ((errors++))
        fi
    else
        echo_warn "Ed25519 private key not found"
    fi
    
    if [[ -f "${keys_dir}/${admin_user}_ed25519.pub" ]]; then
        echo_pass "Ed25519 public key exists"
    else
        echo_warn "Ed25519 public key not found"
    fi
    
    if [[ -f "${keys_dir}/${admin_user}_rsa4096" ]]; then
        echo_pass "RSA-4096 private key exists"
        if [[ $(stat -c %a "${keys_dir}/${admin_user}_rsa4096") == "600" ]]; then
            echo_pass "RSA-4096 private key has correct permissions (600)"
        else
            echo_fail "RSA-4096 private key has incorrect permissions"
            ((errors++))
        fi
    else
        echo_warn "RSA-4096 private key not found"
    fi
    
    return $errors
}

test_authorized_keys() {
    local admin_user=$1
    echo_info "Testing authorized_keys setup..."
    
    local auth_keys="/home/${admin_user}/.ssh/authorized_keys"
    
    if [[ -f "$auth_keys" ]]; then
        echo_pass "authorized_keys file exists"
        
        if [[ $(stat -c %a "$auth_keys") == "600" ]]; then
            echo_pass "authorized_keys has correct permissions (600)"
        else
            echo_fail "authorized_keys has incorrect permissions"
            return 1
        fi
        
        if [[ $(stat -c %U "$auth_keys") == "$admin_user" ]]; then
            echo_pass "authorized_keys has correct ownership"
        else
            echo_fail "authorized_keys has incorrect ownership"
            return 1
        fi
        
        local key_count=$(wc -l < "$auth_keys")
        echo_pass "authorized_keys contains $key_count key(s)"
        
    else
        echo_fail "authorized_keys file not found"
        return 1
    fi
    
    return 0
}

# Main validation
main() {
    echo "SSH Hardening Validation"
    echo "========================"
    echo
    
    # Get parameters
    local admin_user=${1:-admin}
    local ssh_port=${2:-2222}
    local keys_dir=${3:-}
    
    # Auto-detect keys directory if not provided
    if [[ -z "$keys_dir" ]]; then
        keys_dir=$(find /root -maxdepth 1 -name "ssh-generated-keys-*" -type d | sort | tail -1)
        if [[ -n "$keys_dir" ]]; then
            echo_info "Auto-detected keys directory: $keys_dir"
        else
            echo_warn "No keys directory specified and none found"
        fi
    fi
    
    local tests_passed=0
    local tests_total=0
    
    # Run tests
    ((tests_total++)); test_ssh_config && ((tests_passed++))
    ((tests_total++)); test_ssh_service && ((tests_passed++))
    ((tests_total++)); test_ssh_port "$ssh_port" && ((tests_passed++))
    ((tests_total++)); test_root_login_disabled && ((tests_passed++))
    ((tests_total++)); test_password_auth_disabled && ((tests_passed++))
    ((tests_total++)); test_pubkey_auth_enabled && ((tests_passed++))
    ((tests_total++)); test_user_restrictions "$admin_user" && ((tests_passed++))
    
    if [[ -n "$keys_dir" ]]; then
        ((tests_total++)); test_key_files "$keys_dir" "$admin_user" && ((tests_passed++))
    fi
    
    ((tests_total++)); test_authorized_keys "$admin_user" && ((tests_passed++))
    
    # Summary
    echo
    echo "Validation Summary"
    echo "=================="
    echo "Tests passed: $tests_passed/$tests_total"
    
    if [[ $tests_passed -eq $tests_total ]]; then
        echo_pass "All tests passed! SSH hardening appears successful."
        return 0
    else
        echo_warn "Some tests failed. Please review the configuration."
        return 1
    fi
}

# Usage information
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [admin_user] [ssh_port] [keys_directory]"
    echo
    echo "Parameters (all optional):"
    echo "  admin_user      - Admin username (default: admin)"
    echo "  ssh_port        - SSH port number (default: 2222)"
    echo "  keys_directory  - Path to generated keys (auto-detected if not provided)"
    echo
    echo "Examples:"
    echo "  $0                              # Use defaults"
    echo "  $0 myuser                       # Custom user"
    echo "  $0 myuser 2222                  # Custom user and port"
    echo "  $0 myuser 2222 /root/keys       # All parameters"
    exit 0
fi

# Run validation
main "$@"
