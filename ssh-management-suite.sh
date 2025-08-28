#!/usr/bin/env bash
# SSH Management Suite - Complete Single File Version
# Includes hardening, multi-IP, key display, rollback, and validation
# v3.4 - Improved socket handling and function organization

set -Eeuo pipefail

VERSION="3.4"
NOW=""
REPORT=""
BACKUP_DIR=""
ROLLBACK=""
BACKUP_INDEX=""
CHANGED_INDEX=""
SSH_SERVICE=""

# Core utility functions
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root (sudo -i or sudo $0)"; exit 1
  fi
}

timestamp() { date +%F-%H%M%S; }

ASK() {
  local prompt="$1"
  local ans
  while true; do
    echo -n "$prompt [y/n]: "
    read -r ans </dev/tty 2>/dev/null || {
      echo "Unable to read from terminal. Defaulting to 'n': $prompt"
      return 1
    }
    case "${ans:-}" in
      [Yy]) return 0 ;;
      [Nn]) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# SSH service detection functions
detect_ssh_service() {
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    echo sshd
  else
    echo ssh
  fi
}

get_current_ssh_port() {
  grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22"
}

get_current_allow_users() {
  grep -E "^AllowUsers\s+" /etc/ssh/sshd_config 2>/dev/null | sed 's/^AllowUsers\s*//' || echo ""
}

# Improved SSH socket handling
handle_ssh_sockets() {
  local action="$1"  # "disable" or "check"
  local sockets=("ssh.socket" "sshd.socket")
  
  case "$action" in
    "disable")
      echo "Disabling SSH socket services to prevent port conflicts..." | tee -a "$REPORT"
      for socket in "${sockets[@]}"; do
        if systemctl list-unit-files | grep -q "^${socket}"; then
          echo "Processing $socket..." | tee -a "$REPORT"
          systemctl stop "$socket" >/dev/null 2>&1 || true
          systemctl disable "$socket" >/dev/null 2>&1 || true
          systemctl mask "$socket" >/dev/null 2>&1 || true
          echo "systemctl unmask $socket && systemctl enable $socket" >> "$ROLLBACK"
        fi
      done
      ;;
    "check")
      echo "Checking SSH socket status:"
      for socket in "${sockets[@]}"; do
        if systemctl list-unit-files | grep -q "^${socket}"; then
          local status=$(systemctl is-active "$socket" 2>/dev/null || echo "inactive")
          local enabled=$(systemctl is-enabled "$socket" 2>/dev/null || echo "disabled")
          echo "  $socket: $status ($enabled)"
        fi
      done
      ;;
  esac
}

# Improved port verification
verify_ssh_port() {
  local expected_port="$1"
  local max_attempts=15
  local attempt=1
  
  echo "Verifying SSH is listening on port $expected_port..." | tee -a "$REPORT"
  
  while [[ $attempt -le $max_attempts ]]; do
    if netstat -tlnp 2>/dev/null | grep ":${expected_port} " | grep -q sshd || \
       ss -tlnp 2>/dev/null | grep ":${expected_port} " | grep -q sshd; then
      echo "✓ SSH is listening on port $expected_port" | tee -a "$REPORT"
      return 0
    fi
    
    echo "Attempt $attempt/$max_attempts: SSH not yet on port $expected_port, waiting..." | tee -a "$REPORT"
    sleep 2
    ((attempt++))
  done
  
  echo "✗ SSH failed to bind to port $expected_port after $max_attempts attempts" | tee -a "$REPORT"
  return 1
}

# Force SSH service restart with socket cleanup
force_ssh_restart() {
  local expected_port="$1"
  
  echo "Force restarting SSH service..." | tee -a "$REPORT"
  
  # Stop everything SSH-related
  systemctl stop "$SSH_SERVICE" >/dev/null 2>&1 || true
  handle_ssh_sockets "disable"
  
  # Kill any remaining SSH processes
  pkill -f sshd >/dev/null 2>&1 || true
  sleep 2
  
  # Verify config before starting
  if ! sshd -t; then
    echo "SSH config test failed! Aborting restart." | tee -a "$REPORT"
    return 1
  fi
  
  # Start the service
  systemctl start "$SSH_SERVICE"
  
  # Verify port binding
  if ! verify_ssh_port "$expected_port"; then
    echo "Port verification failed. Attempting manual port fix..." | tee -a "$REPORT"
    
    # Force the port setting at the top of the config
    local temp_config="/tmp/sshd_config_fix.$$"
    {
      echo "Port $expected_port"
      grep -v "^Port " /etc/ssh/sshd_config
    } > "$temp_config"
    
    if sshd -t -f "$temp_config"; then
      cp "$temp_config" /etc/ssh/sshd_config
      systemctl restart "$SSH_SERVICE"
      sleep 2
      verify_ssh_port "$expected_port"
    fi
    
    rm -f "$temp_config"
  fi
}

# Utility functions
random_pass() { 
  openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

validate_network() {
  local input="$1"
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip="${input%/*}"
    local cidr="${input#*/}"
    if [[ "$cidr" -gt 32 ]] || [[ "$cidr" -lt 1 ]]; then return 1; fi
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
      if [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then return 1; fi
    done
    return 0
  elif [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -ra octets <<< "$input"
    for octet in "${octets[@]}"; do
      if [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then return 1; fi
    done
    return 0
  elif [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ ${#input} -le 253 ]]; then
    return 0
  else
    return 1
  fi
}

# File management functions
backup_file() {
  local src="$1"
  local dst="${BACKUP_DIR}/$(basename "$src").${NOW}.bak"
  if [[ -e "$src" ]]; then
    cp -a "$src" "$dst"
    echo "Backup -> $dst" | tee -a "$REPORT"
    echo "$dst" >> "$BACKUP_INDEX"
  fi
}

install_file_with_backup() {
  local target="$1"
  local content="$2"
  local temp_file="${target}.tmp.$$"
  
  mkdir -p "$(dirname "$target")"
  if [[ -e "$target" ]]; then
    backup_file "$target"
  fi
  
  if printf "%s" "$content" > "$temp_file" && mv "$temp_file" "$target"; then
    echo "Updated $target" | tee -a "$REPORT"
    echo "$target" >> "$CHANGED_INDEX"
    
    if [[ -e "${BACKUP_DIR}/$(basename "$target").${NOW}.bak" ]]; then
      echo "cp '${BACKUP_DIR}/$(basename "$target").${NOW}.bak' '$target'" >> "$ROLLBACK"
    else
      echo "rm -f '$target'" >> "$ROLLBACK"
    fi
    return 0
  else
    rm -f "$temp_file"
    echo "ERROR: Failed to update $target" | tee -a "$REPORT"
    return 1
  fi
}

# Main SSH hardening function
ssh_hardening_main() {
  NOW="$(timestamp)"
  REPORT="/root/ssh-hardening-report-${NOW}.txt"
  BACKUP_DIR="/root/ssh-hardening-backups-${NOW}"
  ROLLBACK="/root/ssh-hardening-rollback-${NOW}.sh"
  BACKUP_INDEX="${BACKUP_DIR}/_backup-index.txt"
  CHANGED_INDEX="${BACKUP_DIR}/_changed-files.txt"
  mkdir -p "$BACKUP_DIR"
  touch "$BACKUP_INDEX" "$CHANGED_INDEX"
  SSH_SERVICE="$(detect_ssh_service)"
  
  echo "SSH Hardening & Key Report - ${NOW}" > "$REPORT"
  echo "Host: $(hostname -f 2>/dev/null || hostname)" >> "$REPORT"
  
  echo "#!/usr/bin/env bash" > "$ROLLBACK"
  echo "set -Eeuo pipefail" >> "$ROLLBACK"
  echo "echo 'Rolling back SSH hardening changes...'" >> "$ROLLBACK"
  chmod +x "$ROLLBACK"
  
  # Get configuration parameters
  read -r -p "Admin username (default: admin): " ADMIN </dev/tty || ADMIN="admin"
  ADMIN="${ADMIN:-admin}"
  
  while true; do
    read -r -p "SSH port (default: 2222): " SSH_PORT </dev/tty || SSH_PORT="2222"
    SSH_PORT="${SSH_PORT:-2222}"
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [[ "$SSH_PORT" -ge 1024 ]] && [[ "$SSH_PORT" -le 65535 ]]; then
      break
    else
      echo "Invalid port. Please enter a number between 1024-65535."
    fi
  done
  
  read -r -p "Allow from (CIDR/IP, empty = any): " ALLOW_FROM </dev/tty || ALLOW_FROM=""
  
  # Create admin user
  if ASK "Create/ensure admin user '${ADMIN}' with sudo?"; then
    if id "$ADMIN" &>/dev/null; then
      echo "User '$ADMIN' exists." | tee -a "$REPORT"
    else
      adduser --disabled-password --gecos "SSH Admin User" "$ADMIN"
      echo "Created user '$ADMIN'." | tee -a "$REPORT"
      echo "userdel -r '$ADMIN'" >> "$ROLLBACK"
    fi
    
    usermod -aG sudo "$ADMIN"
    local admin_pass="$(random_pass)"
    echo "$ADMIN:$admin_pass" | chpasswd
    echo "Admin credentials: $ADMIN / $admin_pass" >> "$REPORT"
  fi
  
  # Generate SSH keys
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  mkdir -p "$keys_dir"
  local pubkeys_out="${keys_dir}/ALL_PUBLIC_KEYS.txt"
  echo "SSH Key Information:" > "$pubkeys_out"
  
  local has_keys=false
  
  if ASK "Generate encrypted Ed25519 key for '${ADMIN}'?"; then
    local pass_ed="$(random_pass)"
    ssh-keygen -t ed25519 -a 100 -N "${pass_ed}" -C "${ADMIN}@$(hostname)-ed25519" -f "${keys_dir}/${ADMIN}_ed25519" >/dev/null 2>&1
    echo "Generated Ed25519 keypair" | tee -a "$REPORT"
    
    echo "### ${ADMIN} Ed25519 Key" >> "$pubkeys_out"
    echo "Private key: ${keys_dir}/${ADMIN}_ed25519" >> "$pubkeys_out"
    echo "Passphrase: ${pass_ed}" >> "$pubkeys_out"
    cat "${keys_dir}/${ADMIN}_ed25519.pub" >> "$pubkeys_out"
    echo >> "$pubkeys_out"
    
    has_keys=true
  fi
  
  if ASK "Also generate RSA-4096 key for compatibility?"; then
    local pass_rsa="$(random_pass)"
    ssh-keygen -t rsa -b 4096 -o -a 100 -N "${pass_rsa}" -C "${ADMIN}@$(hostname)-rsa4096" -f "${keys_dir}/${ADMIN}_rsa4096" >/dev/null 2>&1
    echo "Generated RSA-4096 keypair" | tee -a "$REPORT"
    
    echo "### ${ADMIN} RSA-4096 Key" >> "$pubkeys_out"
    echo "Private key: ${keys_dir}/${ADMIN}_rsa4096" >> "$pubkeys_out"
    echo "Passphrase: ${pass_rsa}" >> "$pubkeys_out"
    cat "${keys_dir}/${ADMIN}_rsa4096.pub" >> "$pubkeys_out"
    echo >> "$pubkeys_out"
    
    has_keys=true
  fi
  
  # Install SSH keys
  if [[ "$has_keys" == true ]] && ASK "Install public keys to ~$ADMIN/.ssh/authorized_keys?"; then
    su - "$ADMIN" -s /bin/bash -c 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys'
    
    local admin_auth_keys="/home/$ADMIN/.ssh/authorized_keys"
    if [[ -s "$admin_auth_keys" ]]; then
      backup_file "$admin_auth_keys"
    fi
    
    [[ -f "${keys_dir}/${ADMIN}_ed25519.pub" ]] && cat "${keys_dir}/${ADMIN}_ed25519.pub" >> "$admin_auth_keys"
    [[ -f "${keys_dir}/${ADMIN}_rsa4096.pub" ]] && cat "${keys_dir}/${ADMIN}_rsa4096.pub" >> "$admin_auth_keys"
    
    chown "$ADMIN:$ADMIN" "$admin_auth_keys"
    chmod 600 "$admin_auth_keys"
    chmod 700 "/home/$ADMIN/.ssh"
    
    echo "$admin_auth_keys" >> "$CHANGED_INDEX"
  fi
  
  # Apply SSH hardening
  if ASK "Apply SSH hardening configuration?"; then
    local allow_users=""
    if [[ -n "$ALLOW_FROM" ]]; then
      allow_users="AllowUsers ${ADMIN}@${ALLOW_FROM}"
    else
      allow_users="AllowUsers ${ADMIN}"
    fi
    
    local ssh_config="# SSH Hardening Configuration - Applied ${NOW}
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
${allow_users}
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
Protocol 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
"

    install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
  fi
  
  # Restart SSH service with improved handling
  if ASK "Restart SSH service to apply changes?"; then
    if sshd -t; then
      echo "SSH config test: PASSED" | tee -a "$REPORT"
      
      # Use improved restart function
      force_ssh_restart "$SSH_PORT"
      
    else
      echo "SSH config test failed!" | tee -a "$REPORT"
      return 1
    fi
  fi
  
  # Final report
  echo "Connection test:" >> "$REPORT"
  if [[ -f "${keys_dir}/${ADMIN}_ed25519" ]]; then
    echo "ssh -i ${keys_dir}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')" >> "$REPORT"
  fi
  echo "Rollback: $ROLLBACK" >> "$REPORT"
  
  chmod 600 "$keys_dir"/* 2>/dev/null || true
  chmod 644 "$keys_dir"/*.pub 2>/dev/null || true
  
  echo "SSH Hardening Complete!"
  echo "Report: $REPORT"
  echo "Keys: $keys_dir"
}

# Multi-IP configuration function
multi_ip_config() {
  local current_port=$(get_current_ssh_port)
  echo "Multi-IP Configuration (Current port: $current_port)"
  
  # Get username with validation
  while true; do
    read -r -p "SSH username: " username </dev/tty
    if [[ -n "$username" ]] && [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      if id "$username" &>/dev/null; then
        break
      else
        if ASK "User '$username' does not exist. Continue?"; then break; fi
      fi
    else
      echo "Invalid username. Use only letters, numbers, underscore, and hyphen."
    fi
  done
  
  # Get networks
  echo "Enter networks (empty to finish):"
  local networks=()
  while true; do
    read -r -p "Network/IP: " network </dev/tty
    [[ -z "$network" ]] && break
    if validate_network "$network"; then
      networks+=("$network")
      echo "Added: $network"
    else
      echo "Invalid network format: $network"
    fi
  done
  
  [[ ${#networks[@]} -eq 0 ]] && { echo "No networks specified."; return 1; }
  
  # Build AllowUsers line
  local allow_users_line="AllowUsers"
  for net in "${networks[@]}"; do
    allow_users_line="$allow_users_line ${username}@${net}"
  done
  
  echo "Configuration: $allow_users_line"
  ASK "Apply this configuration?" || return 1
  
  # Apply configuration
  local backup_file="/root/sshd_config.backup.$(timestamp)"
  cp /etc/ssh/sshd_config "$backup_file"
  
  local temp_config="/tmp/sshd_config.$$"
  grep -v "^AllowUsers" /etc/ssh/sshd_config > "$temp_config"
  echo "$allow_users_line" >> "$temp_config"
  
  if sshd -t -f "$temp_config"; then
    cp "$temp_config" /etc/ssh/sshd_config
    
    # Use improved restart handling
    SSH_SERVICE="$(detect_ssh_service)"
    handle_ssh_sockets "disable"
    systemctl restart "$SSH_SERVICE"
    
    rm -f "$temp_config"
    echo "Multi-IP configuration applied! Backup: $backup_file"
  else
    echo "Configuration test failed!"
    rm -f "$temp_config"
    return 1
  fi
}

# SSH keys display function
display_ssh_keys() {
  echo "SSH Keys and Passphrases"
  echo "========================"
  
  local key_sessions=()
  for keys_dir in /root/ssh-generated-keys-*; do
    [[ -d "$keys_dir" ]] || continue
    local timestamp=$(basename "$keys_dir" | sed 's/ssh-generated-keys-//')
    key_sessions+=("$timestamp")
  done
  
  [[ ${#key_sessions[@]} -eq 0 ]] && { echo "No key sessions found."; return 0; }
  
  echo "Available sessions:"
  for i in "${!key_sessions[@]}"; do
    echo "$((i+1)). ${key_sessions[$i]}"
  done
  
  read -r -p "Select session (1-${#key_sessions[@]}): " choice </dev/tty
  
  if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#key_sessions[@]} ]]; then
    local session="${key_sessions[$((choice-1))]}"
    local keys_dir="/root/ssh-generated-keys-$session"
    local key_info="$keys_dir/ALL_PUBLIC_KEYS.txt"
    
    if [[ -f "$key_info" ]]; then
      echo
      cat "$key_info"
      echo
      echo "Private key files:"
      find "$keys_dir" -name "*_ed25519" -o -name "*_rsa4096" 2>/dev/null | head -10 || echo "No private keys found"
    else
      echo "Key information not found for session $session"
    fi
  else
    echo "Invalid selection"
  fi
}

# Rollback function
handle_rollback() {
  echo "Rollback Management"
  echo "=================="
  
  local sessions=()
  for report in /root/ssh-hardening-report-* /root/ssh-multi-ip-config-*; do
    [[ -f "$report" ]] || continue
    local timestamp=$(basename "$report" | sed -E 's/ssh-(hardening-report|multi-ip-config)-//' | sed 's/.txt//')
    sessions+=("$timestamp")
  done
  
  [[ ${#sessions[@]} -eq 0 ]] && { echo "No sessions found."; return 0; }
  
  echo "Available sessions:"
  for i in "${!sessions[@]}"; do
    echo "$((i+1)). ${sessions[$i]}"
  done
  
  read -r -p "Select session to rollback (1-${#sessions[@]}): " choice </dev/tty
  
  if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#sessions[@]} ]]; then
    local session="${sessions[$((choice-1))]}"
    
    ASK "Rollback session $session?" || return
    
    local rollback_script="/root/ssh-hardening-rollback-$session.sh"
    if [[ -x "$rollback_script" ]]; then
      echo "Executing rollback script: $rollback_script"
      "$rollback_script"
    else
      # Manual rollback fallback
      echo "No rollback script found, attempting manual restore..."
      for backup in "/root/ssh-hardening-backups-$session"/sshd_config*.bak "/root/sshd_config.backup.$session"; do
        if [[ -f "$backup" ]]; then
          cp "$backup" /etc/ssh/sshd_config
          SSH_SERVICE="$(detect_ssh_service)"
          handle_ssh_sockets "disable"
          systemctl restart "$SSH_SERVICE"
          echo "Restored SSH config from $backup"
          return
        fi
      done
      echo "No backup found for session $session"
    fi
  else
    echo "Invalid selection"
  fi
}

# Enhanced validation function
run_validation() {
  echo "SSH Configuration Validation"
  echo "============================"
  
  local tests_passed=0
  local tests_total=8
  
  # Test 1: SSH config syntax
  if sshd -t 2>/dev/null; then
    echo "[PASS] SSH config syntax valid"
    ((tests_passed++))
  else
    echo "[FAIL] SSH config syntax invalid"
    sshd -t
  fi
  
  # Test 2: SSH service status
  SSH_SERVICE="$(detect_ssh_service)"
  if systemctl is-active "$SSH_SERVICE" >/dev/null 2>&1; then
    echo "[PASS] SSH service ($SSH_SERVICE) is running"
    ((tests_passed++))
  else
    echo "[FAIL] SSH service ($SSH_SERVICE) is not running"
    systemctl status "$SSH_SERVICE" --no-pager -l
  fi
  
  # Test 3: Port binding
  local configured_port=$(get_current_ssh_port)
  if netstat -tlnp 2>/dev/null | grep ":$configured_port " | grep -q sshd || \
     ss -tlnp 2>/dev/null | grep ":$configured_port " | grep -q sshd; then
    echo "[PASS] SSH listening on configured port $configured_port"
    ((tests_passed++))
  else
    echo "[FAIL] SSH not listening on configured port $configured_port"
    echo "Currently listening on:"
    netstat -tlnp 2>/dev/null | grep sshd || ss -tlnp 2>/dev/null | grep sshd || echo "No SSH ports found"
  fi
  
  # Test 4: Socket conflicts
  handle_ssh_sockets "check"
  local sockets_active=false
  for socket in ssh.socket sshd.socket; do
    if systemctl is-active "$socket" >/dev/null 2>&1; then
      sockets_active=true
      break
    fi
  done
  
  if [[ "$sockets_active" == false ]]; then
    echo "[PASS] No conflicting SSH sockets active"
    ((tests_passed++))
  else
    echo "[WARN] SSH sockets detected (may override port config)"
  fi
  
  # Test 5: Root login
  if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Root login disabled"
    ((tests_passed++))
  else
    echo "[WARN] Root login not explicitly disabled"
  fi
  
  # Test 6: Password authentication
  if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Password authentication disabled"
    ((tests_passed++))
  else
    echo "[WARN] Password authentication not disabled"
  fi
  
  # Test 7: User restrictions
  if grep -q "^AllowUsers" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] User access restrictions configured"
    local users=$(get_current_allow_users)
    echo "       AllowUsers: $users"
    ((tests_passed++))
  else
    echo "[WARN] No user access restrictions (any user can attempt login)"
  fi
  
  # Test 8: Key authentication
  if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Public key authentication enabled"
    ((tests_passed++))
  else
    echo "[WARN] Public key authentication not explicitly enabled"
  fi
  
  echo
  echo "Validation Results: $tests_passed/$tests_total tests passed"
  
  if [[ $tests_passed -ge 6 ]]; then
    echo "Status: SSH configuration appears secure"
  elif [[ $tests_passed -ge 4 ]]; then
    echo "Status: SSH configuration has some issues"
  else
    echo "Status: SSH configuration needs attention"
  fi
}

# Menu display function
show_main_menu() {
  clear
  echo "SSH Management Suite v${VERSION}"
  echo "==============================="
  echo "Host: $(hostname)"
  echo "SSH Port: $(get_current_ssh_port)"
  local users=$(get_current_allow_users)
  [[ -n "$users" ]] && echo "AllowUsers: $users"
  echo
  echo "1) Harden SSH (new installation)"
  echo "2) Configure multi-IP access"
  echo "3) Display SSH keys and passphrases"
  echo "4) Rollback previous sessions"
  echo "5) Validate current configuration"
  echo "6) Exit"
  echo
}

# Main function
main() {
  require_root
  
  while true; do
    show_main_menu
    read -r -p "Choose option (1-6): " choice </dev/tty
    
    case "$choice" in
      1) echo; ssh_hardening_main; echo; read -r -p "Press Enter..." </dev/tty ;;
      2) echo; multi_ip_config; echo; read -r -p "Press Enter..." </dev/tty ;;
      3) echo; display_ssh_keys; echo; read -r -p "Press Enter..." </dev/tty ;;
      4) echo; handle_rollback; echo; read -r -p "Press Enter..." </dev/tty ;;
      5) echo; run_validation; echo; read -r -p "Press Enter..." </dev/tty ;;
      6) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid choice. Please select 1-6."; sleep 1 ;;
    esac
  done
}

# Entry point
main "$@"
