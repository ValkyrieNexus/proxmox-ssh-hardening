#!/usr/bin/env bash
# SSH Hardening Validation Script
# Tests the hardened SSH configuration
# v1.0

set -Eeuo pipefail

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