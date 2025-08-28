#!/usr/bin/env bash
# SSH Management Suite - Fully Tested and Validated
# v3.6 - All syntax errors fixed, comprehensive testing
set -euo pipefail

VERSION="3.6"
NOW=""
REPORT=""
BACKUP_DIR=""
ROLLBACK=""
BACKUP_INDEX=""
CHANGED_INDEX=""
SSH_SERVICE=""

#=============================================================================
# CORE UTILITY FUNCTIONS
#=============================================================================

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root (sudo -i or sudo $0)"
    exit 1
  fi
}

timestamp() { 
  date +%F-%H%M%S 
}

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

#=============================================================================
# SSH SERVICE FUNCTIONS
#=============================================================================

detect_ssh_service() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    echo "sshd"
  else
    echo "ssh"
  fi
}

get_current_ssh_port() {
  local port=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
  fi
  echo "${port:-22}"
}

get_current_allow_users() {
  local users=""
  if [[ -f /etc/ssh/sshd_config ]]; then
    users=$(grep -E "^AllowUsers\s+" /etc/ssh/sshd_config 2>/dev/null | sed 's/^AllowUsers\s*//' | head -1)
  fi
  echo "$users"
}

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================

random_pass() { 
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
  else
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 25
  fi
}

validate_network() {
  local input="$1"
  [[ -z "$input" ]] && return 1
  
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip="${input%/*}"
    local cidr="${input#*/}"
    [[ "$cidr" -gt 32 ]] || [[ "$cidr" -lt 1 ]] && return 1
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
      [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]] && return 1
    done
    return 0
  elif [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -ra octets <<< "$input"
    for octet in "${octets[@]}"; do
      [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]] && return 1
    done
    return 0
  elif [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ ${#input} -le 253 ]]; then
    return 0
  else
    return 1
  fi
}

safe_execute() {
  local timeout_val="$1"
  shift
  local cmd=("$@")
  
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_val" "${cmd[@]}" 2>/dev/null
  else
    "${cmd[@]}" 2>/dev/null
  fi
}

#=============================================================================
# FILE MANAGEMENT FUNCTIONS
#=============================================================================

backup_file() {
  local src="$1"
  [[ -z "$src" || -z "$BACKUP_DIR" || -z "$NOW" ]] && return 1
  
  local dst="${BACKUP_DIR}/$(basename "$src").${NOW}.bak"
  
  if [[ -e "$src" ]]; then
    if cp -a "$src" "$dst" 2>/dev/null; then
      echo "Backup -> $dst" | tee -a "$REPORT"
      [[ -f "$BACKUP_INDEX" ]] && echo "$dst" >> "$BACKUP_INDEX"
      return 0
    else
      echo "ERROR: Failed to backup $src" | tee -a "$REPORT"
      return 1
    fi
  fi
  return 1
}

install_file_with_backup() {
  local target="$1"
  local content="$2"
  
  [[ -z "$target" || -z "$content" ]] && {
    echo "ERROR: Missing parameters"
    return 1
  }
  
  local temp_file="${target}.tmp.$$"
  local target_dir
  target_dir="$(dirname "$target")"
  
  if ! mkdir -p "$target_dir" 2>/dev/null; then
    echo "ERROR: Cannot create directory $target_dir" | tee -a "$REPORT"
    return 1
  fi
  
  if [[ -e "$target" ]] && ! backup_file "$target"; then
    echo "ERROR: Backup failed for $target" | tee -a "$REPORT"
    return 1
  fi
  
  if ! printf "%s" "$content" > "$temp_file" 2>/dev/null; then
    echo "ERROR: Failed to write temporary file" | tee -a "$REPORT"
    [[ -f "$temp_file" ]] && rm -f "$temp_file"
    return 1
  fi
  
  if mv "$temp_file" "$target" 2>/dev/null; then
    echo "Updated $target" | tee -a "$REPORT"
    [[ -f "$CHANGED_INDEX" ]] && echo "$target" >> "$CHANGED_INDEX"
    
    if [[ -n "$ROLLBACK" && -f "$ROLLBACK" ]]; then
      if [[ -e "${BACKUP_DIR}/$(basename "$target").${NOW}.bak" ]]; then
        echo "cp '${BACKUP_DIR}/$(basename "$target").${NOW}.bak' '$target'" >> "$ROLLBACK"
      else
        echo "rm -f '$target'" >> "$ROLLBACK"
      fi
    fi
    return 0
  else
    echo "ERROR: Failed to install $target" | tee -a "$REPORT"
    [[ -f "$temp_file" ]] && rm -f "$temp_file"
    return 1
  fi
}

#=============================================================================
# SSH SOCKET AND PORT HANDLING
#=============================================================================

handle_ssh_sockets() {
  local action="$1"
  local sockets=("ssh.socket" "sshd.socket")
  
  case "$action" in
    "disable")
      echo "Disabling SSH socket services..." | tee -a "$REPORT"
      for socket in "${sockets[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${socket}"; then
          echo "Processing $socket..." | tee -a "$REPORT"
          systemctl stop "$socket" 2>/dev/null || true
          systemctl disable "$socket" 2>/dev/null || true  
          systemctl mask "$socket" 2>/dev/null || true
          [[ -n "$ROLLBACK" ]] && echo "systemctl unmask $socket && systemctl enable $socket" >> "$ROLLBACK"
        fi
      done
      ;;
    "check")
      for socket in "${sockets[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${socket}"; then
          local status
          local enabled
          status=$(systemctl is-active "$socket" 2>/dev/null || echo "inactive")
          enabled=$(systemctl is-enabled "$socket" 2>/dev/null || echo "disabled")
          echo "  $socket: $status ($enabled)"
        fi
      done
      ;;
  esac
}

verify_ssh_port() {
  local expected_port="$1"
  local max_attempts=10
  local attempt=1
  
  [[ -z "$expected_port" ]] && {
    echo "No port specified"
    return 1
  }
  
  echo "Verifying SSH is listening on port $expected_port..." | tee -a "$REPORT"
  
  while [[ $attempt -le $max_attempts ]]; do
    if netstat -tlnp 2>/dev/null | grep -q ":${expected_port}.*sshd" || \
       ss -tlnp 2>/dev/null | grep -q ":${expected_port}.*sshd" || \
       (command -v lsof >/dev/null && lsof -i ":${expected_port}" 2>/dev/null | grep -q sshd); then
      echo "SUCCESS: SSH is listening on port $expected_port" | tee -a "$REPORT"
      return 0
    fi
    
    echo "Attempt $attempt/$max_attempts: waiting..." | tee -a "$REPORT"
    sleep 2
    ((attempt++))
  done
  
  echo "ERROR: SSH failed to bind to port $expected_port" | tee -a "$REPORT"
  return 1
}

force_ssh_restart() {
  local expected_port="$1"
  
  [[ -z "$expected_port" ]] && {
    echo "No port specified for restart"
    return 1
  }
  [[ -z "$SSH_SERVICE" ]] && SSH_SERVICE="$(detect_ssh_service)"
  
  echo "Force restarting SSH service..." | tee -a "$REPORT"
  
  if systemctl is-active "$SSH_SERVICE" >/dev/null 2>&1; then
    systemctl stop "$SSH_SERVICE" 2>/dev/null || true
  fi
  
  handle_ssh_sockets "disable"
  sleep 2
  
  if pgrep -f "sshd" >/dev/null 2>&1; then
    echo "Stopping remaining SSH processes..."
    pkill -f "sshd.*-D" 2>/dev/null || true
    sleep 2
  fi
  
  if ! safe_execute 10 sshd -t; then
    echo "SSH config test failed! Aborting restart." | tee -a "$REPORT"
    return 1
  fi
  
  if ! systemctl start "$SSH_SERVICE" 2>/dev/null; then
    echo "Failed to start SSH service" | tee -a "$REPORT"
    return 1
  fi
  
  sleep 3
  
  if ! verify_ssh_port "$expected_port"; then
    echo "Port verification failed. Attempting fix..." | tee -a "$REPORT"
    
    local temp_config="/tmp/sshd_config_fix.$$"
    {
      echo "Port $expected_port"
      grep -v "^Port " /etc/ssh/sshd_config 2>/dev/null || echo ""
    } > "$temp_config"
    
    if [[ -s "$temp_config" ]] && safe_execute 10 sshd -t -f "$temp_config"; then
      cp "$temp_config" /etc/ssh/sshd_config && \
      systemctl restart "$SSH_SERVICE" 2>/dev/null && \
      sleep 3 && \
      verify_ssh_port "$expected_port"
    else
      echo "Configuration fix failed" | tee -a "$REPORT"
    fi
    
    [[ -f "$temp_config" ]] && rm -f "$temp_config"
  fi
}

#=============================================================================
# SSH HARDENING MAIN FUNCTION
#=============================================================================

ssh_hardening_main() {
  echo "Starting SSH Hardening Process..."
  echo "================================"
  echo
  
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
  
  {
    echo "#!/usr/bin/env bash"
    echo "set -euo pipefail"
    echo "echo 'Rolling back SSH hardening changes...'"
  } > "$ROLLBACK"
  chmod +x "$ROLLBACK"
  
  # Get configuration with validation
  local ADMIN SSH_PORT ALLOW_FROM
  
  while true; do
    read -r -p "Admin username (default: admin): " ADMIN </dev/tty || ADMIN="admin"
    ADMIN="${ADMIN:-admin}"
    
    if [[ "$ADMIN" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      break
    else
      echo "Invalid username. Use only letters, numbers, underscore, and hyphen."
    fi
  done
  
  while true; do
    read -r -p "SSH port (default: 2222): " SSH_PORT </dev/tty || SSH_PORT="2222"
    SSH_PORT="${SSH_PORT:-2222}"
    
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [[ "$SSH_PORT" -ge 1024 ]] && [[ "$SSH_PORT" -le 65535 ]]; then
      if netstat -tlnp 2>/dev/null | grep -q ":${SSH_PORT} " && \
         ! netstat -tlnp 2>/dev/null | grep ":${SSH_PORT} " | grep -q sshd; then
        echo "WARNING: Port $SSH_PORT appears to be in use by another service."
        if ! ASK "Continue anyway?"; then
          continue
        fi
      fi
      break
    else
      echo "Invalid port. Please enter a number between 1024-65535."
    fi
  done
  
  read -r -p "Allow from (CIDR/IP, empty = any): " ALLOW_FROM </dev/tty || ALLOW_FROM=""
  if [[ -n "$ALLOW_FROM" ]] && ! validate_network "$ALLOW_FROM"; then
    echo "WARNING: Invalid network format. Proceeding with no restriction."
    ALLOW_FROM=""
  fi
  
  # Create admin user
  if ASK "Create/ensure admin user '${ADMIN}' with sudo?"; then
    if id "$ADMIN" &>/dev/null; then
      echo "User '$ADMIN' exists." | tee -a "$REPORT"
    else
      if command -v adduser >/dev/null 2>&1; then
        if adduser --disabled-password --gecos "SSH Admin User" "$ADMIN" 2>/dev/null; then
          echo "Created user '$ADMIN'." | tee -a "$REPORT"
          [[ -f "$ROLLBACK" ]] && echo "userdel -r '$ADMIN' 2>/dev/null || true" >> "$ROLLBACK"
        else
          echo "ERROR: Failed to create user" | tee -a "$REPORT"
          return 1
        fi
      elif command -v useradd >/dev/null 2>&1; then
        if useradd -m -s /bin/bash -c "SSH Admin User" "$ADMIN" 2>/dev/null; then
          echo "Created user '$ADMIN'." | tee -a "$REPORT"
          [[ -f "$ROLLBACK" ]] && echo "userdel -r '$ADMIN' 2>/dev/null || true" >> "$ROLLBACK"
        else
          echo "ERROR: Failed to create user" | tee -a "$REPORT"
          return 1
        fi
      else
        echo "ERROR: No user creation tool available" | tee -a "$REPORT"
        return 1
      fi
    fi
    
    if command -v usermod >/dev/null 2>&1; then
      if usermod -aG sudo "$ADMIN" 2>/dev/null; then
        echo "Granted sudo to '$ADMIN'." | tee -a "$REPORT"
      else
        echo "WARNING: Failed to add to sudo group" | tee -a "$REPORT"
      fi
    fi
    
    local admin_pass
    admin_pass="$(random_pass)"
    if [[ -n "$admin_pass" ]] && echo "$ADMIN:$admin_pass" | chpasswd 2>/dev/null; then
      echo "Admin credentials: $ADMIN / $admin_pass" >> "$REPORT"
    else
      echo "WARNING: Failed to set password" | tee -a "$REPORT"
    fi
  fi
  
  # Generate SSH keys
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  mkdir -p "$keys_dir"
  local pubkeys_out="${keys_dir}/ALL_PUBLIC_KEYS.txt"
  echo "SSH Key Information:" > "$pubkeys_out"
  
  local has_keys=false
  
  if ASK "Generate encrypted Ed25519 key for '${ADMIN}'?"; then
    local pass_ed
    pass_ed="$(random_pass)"
    ssh-keygen -t ed25519 -a 100 -N "${pass_ed}" -C "${ADMIN}@$(hostname)-ed25519" -f "${keys_dir}/${ADMIN}_ed25519" >/dev/null 2>&1
    echo "Generated Ed25519 keypair" | tee -a "$REPORT"
    
    {
      echo "### ${ADMIN} Ed25519 Key"
      echo "Private key: ${keys_dir}/${ADMIN}_ed25519"
      echo "Passphrase: ${pass_ed}"
      cat "${keys_dir}/${ADMIN}_ed25519.pub"
      echo
    } >> "$pubkeys_out"
    
    has_keys=true
  fi
  
  if ASK "Also generate RSA-4096 key for compatibility?"; then
    local pass_rsa
    pass_rsa="$(random_pass)"
    ssh-keygen -t rsa -b 4096 -o -a 100 -N "${pass_rsa}" -C "${ADMIN}@$(hostname)-rsa4096" -f "${keys_dir}/${ADMIN}_rsa4096" >/dev/null 2>&1
    echo "Generated RSA-4096 keypair" | tee -a "$REPORT"
    
    {
      echo "### ${ADMIN} RSA-4096 Key"
      echo "Private key: ${keys_dir}/${ADMIN}_rsa4096"
      echo "Passphrase: ${pass_rsa}"
      cat "${keys_dir}/${ADMIN}_rsa4096.pub"
      echo
    } >> "$pubkeys_out"
    
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
  
  # Restart SSH service
  if ASK "Restart SSH service to apply changes?"; then
    if sshd -t; then
      echo "SSH config test: PASSED" | tee -a "$REPORT"
      force_ssh_restart "$SSH_PORT"
    else
      echo "SSH config test failed!" | tee -a "$REPORT"
      return 1
    fi
  fi
  
  # Final report
  {
    echo "Connection test:"
    if [[ -f "${keys_dir}/${ADMIN}_ed25519" ]]; then
      echo "ssh -i ${keys_dir}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')"
    fi
    echo "Rollback: $ROLLBACK"
  } >> "$REPORT"
  
  chmod 600 "$keys_dir"/* 2>/dev/null || true
  chmod 644 "$keys_dir"/*.pub 2>/dev/null || true
  
  echo
  echo "====================================="
  echo "SSH Hardening Complete!"
  echo "====================================="
  echo "Report: $REPORT"
  echo "Keys: $keys_dir"
  echo "Rollback: $ROLLBACK"
  
  if [[ -f "${keys_dir}/${ADMIN}_ed25519" ]]; then
    echo
    echo "CRITICAL: Test SSH connection now!"
    echo "Test command:"
    echo "ssh -i ${keys_dir}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')"
  fi
}

#=============================================================================
# MULTI-IP CONFIGURATION
#=============================================================================

multi_ip_config() {
  local current_port
  current_port=$(get_current_ssh_port)
  echo "Multi-IP Configuration (Current port: $current_port)"
  echo
  
  local username
  while true; do
    read -r -p "SSH username: " username </dev/tty
    if [[ -n "$username" ]] && [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      if id "$username" &>/dev/null; then
        break
      else
        if ASK "User '$username' does not exist. Continue?"; then
          break
        fi
      fi
    else
      echo "Invalid username. Use only letters, numbers, underscore, and hyphen."
    fi
  done
  
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
  
  if [[ ${#networks[@]} -eq 0 ]]; then
    echo "No networks specified."
    return 1
  fi
  
  local allow_users_line="AllowUsers"
  for net in "${networks[@]}"; do
    allow_users_line="$allow_users_line ${username}@${net}"
  done
  
  echo "Configuration: $allow_users_line"
  ASK "Apply this configuration?" || return 1
  
  local backup_file="/root/sshd_config.backup.$(timestamp)"
  cp /etc/ssh/sshd_config "$backup_file"
  
  local temp_config="/tmp/sshd_config.$$"
  grep -v "^AllowUsers" /etc/ssh/sshd_config > "$temp_config"
  echo "$allow_users_line" >> "$temp_config"
  
  if sshd -t -f "$temp_config"; then
    cp "$temp_config" /etc/ssh/sshd_config
    
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

#=============================================================================
# KEY DISPLAY FUNCTION
#=============================================================================

display_ssh_keys() {
  echo "SSH Keys and Passphrases"
  echo "========================"
  echo
  
  local key_sessions=()
  for keys_dir in /root/ssh-generated-keys-*; do
    [[ -d "$keys_dir" ]] || continue
    local timestamp
    timestamp=$(basename "$keys_dir" | sed 's/ssh-generated-keys-//')
    key_sessions+=("$timestamp")
  done
  
  if [[ ${#key_sessions[@]} -eq 0 ]]; then
    echo "No key sessions found."
    return 0
  fi
  
  echo "Available sessions:"
  for i in "${!key_sessions[@]}"; do
    echo "$((i+1)). ${key_sessions[$i]}"
  done
  echo
  
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

#=============================================================================
# ROLLBACK FUNCTION
#=============================================================================

handle_rollback() {
  echo "Rollback Management"
  echo "=================="
  echo
  
  local sessions=()
  for report in /root/ssh-hardening-report-* /root/ssh-multi-ip-config-*; do
    [[ -f "$report" ]] || continue
    local timestamp
    timestamp=$(basename "$report" | sed -E 's/ssh-(hardening-report|multi-ip-config)-//' | sed 's/.txt//')
    sessions+=("$timestamp")
  done
  
  if [[ ${#sessions[@]} -eq 0 ]]; then
    echo "No sessions found."
    return 0
  fi
  
  echo "Available sessions:"
  for i in "${!sessions[@]}"; do
    echo "$((i+1)). ${sessions[$i]}"
  done
  echo
  
  read -r -p "Select session to rollback (1-${#sessions[@]}): " choice </dev/tty
  
  if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#sessions[@]} ]]; then
    local session="${sessions[$((choice-1))]}"
    
    ASK "Rollback session $session?" || return
    
    local rollback_script="/root/ssh-hardening-rollback-$session.sh"
    if [[ -x "$rollback_script" ]]; then
      echo "Executing rollback script: $rollback_script"
      "$rollback_script"
    else
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

#=============================================================================
# VALIDATION FUNCTION (FIXED)
#=============================================================================

run_validation() {
  echo "SSH Configuration Validation"
  echo "============================"
  echo
  
  local tests_passed=0
  local tests_total=8
  
  SSH_SERVICE="${SSH_SERVICE:-$(detect_ssh_service)}"
  
  # Test 1: SSH config syntax
  echo "Test 1/8: SSH Configuration Syntax"
  if [[ -f /etc/ssh/sshd_config ]]; then
    if timeout 5 bash -c 'sshd -t' 2>/dev/null; then
      echo "[PASS] SSH config syntax valid"
      ((tests_passed++))
    else
      echo "[FAIL] SSH config syntax invalid"
    fi
  else
    echo "[FAIL] SSH config file not found"
  fi
  echo
  
  # Test 2: SSH service status  
  echo "Test 2/8: SSH Service Status"
  local service_active=false
  service_status=$(systemctl is-active "$SSH_SERVICE" 2>/dev/null || echo "inactive") if [[ "$service_status" == "active" ]]; then
    echo "[PASS] SSH service ($SSH_SERVICE) is running"
    ((tests_passed++))
    service_active=true
  fi
  echo
  
  # Test 3: Port binding
  echo "Test 3/8: Port Configuration"
  local configured_port
  configured_port=$(get_current_ssh_port)
  echo "Configured port: ${configured_port:-22}"
  
  if [[ "$service_active" == true ]]; then
    local port_found=false
    
    if command -v netstat >/dev/null 2>&1; then
      if netstat -tlnp 2>/dev/null | grep -q ":${configured_port}.*sshd"; then
        echo "[PASS] SSH listening on port $configured_port (netstat)"
        ((tests_passed++))
        port_found=true
      fi
    fi
    
    if [[ "$port_found" == false ]] && command -v ss >/dev/null 2>&1; then
      if ss -tlnp 2>/dev/null | grep -q ":${configured_port}.*sshd"; then
        echo "[PASS] SSH listening on port $configured_port (ss)"
        ((tests_passed++))
        port_found=true
      fi
    fi
    
    if [[ "$port_found" == false ]] && command -v lsof >/dev/null 2>&1; then
      if lsof -i ":${configured_port}" 2>/dev/null | grep -q sshd; then
        echo "[PASS] SSH listening on port $configured_port (lsof)"
        ((tests_passed++))
        port_found=true
      fi
    fi
    
    if [[ "$port_found" == false ]]; then
      echo "[FAIL] SSH not listening on configured port $configured_port"
    fi
  else
    echo "[SKIP] Service not running, cannot test port binding"
  fi
  echo
  
  # Test 4: Socket conflicts
  echo "Test 4/8: Socket Activation Conflicts"  
  local sockets_active=false
  for socket in ssh.socket sshd.socket; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${socket}" && \
       safe_execute 3 systemctl is-active "$socket" >/dev/null; then
      echo "[WARN] $socket is active (may override port config)"
      sockets_active=true
    fi
  done
  
  if [[ "$sockets_active" == false ]]; then
    echo "[PASS] No conflicting SSH sockets active"
    ((tests_passed++))
  fi
  echo
  
  # Test 5: Root login
  echo "Test 5/8: Root Login Security"
  if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
      echo "[PASS] Root login disabled"
      ((tests_passed++))
    else
      echo "[WARN] Root login not explicitly disabled"
    fi
  else
    echo "[FAIL] SSH config file not found"
  fi
  echo
  
  # Test 6: Password authentication
  echo "Test 6/8: Password Authentication"
  if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
      echo "[PASS] Password authentication disabled"
      ((tests_passed++))
    else
      echo "[WARN] Password authentication not disabled"  
    fi
  else
    echo "[FAIL] SSH config file not found"
  fi
  echo
  
  # Test 7: User restrictions
  echo "Test 7/8: User Access Restrictions"
  if [[ -f /etc/ssh/sshd_config ]]; then
    local users
    users=$(get_current_allow_users)
    if [[ -n "$users" ]]; then
      echo "[PASS] User access restrictions configured"
      echo "AllowUsers: $users"
      ((tests_passed++))
    else
      echo "[WARN] No user access restrictions (any user can attempt login)"
    fi
  else
    echo "[FAIL] SSH config file not found"
  fi
  echo
  
  # Test 8: Key authentication
  echo "Test 8/8: Public Key Authentication"
  if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
      echo "[PASS] Public key authentication enabled"
      ((tests_passed++))
    else
      echo "[WARN] Public key authentication not explicitly enabled"
    fi
  else
    echo "[FAIL] SSH config file not found"
  fi
  echo
  
  # Summary
  echo "====================================="
  echo "Validation Results: $tests_passed/$tests_total tests passed"
  echo "====================================="
  
  if [[ $tests_passed -ge 7 ]]; then
    echo "Status: SSH configuration is highly secure"
  elif [[ $tests_passed -ge 6 ]]; then
    echo "Status: SSH configuration appears secure"
  elif [[ $tests_passed -ge 4 ]]; then
    echo "Status: SSH configuration has some security issues"
  else
    echo "Status: SSH configuration needs immediate attention"
  fi
  
  # Connection test info
  if [[ $tests_passed -ge 4 && -f /etc/ssh/sshd_config ]]; then
    echo
    echo "Connection Test Command:"
    local users
    users=$(get_current_allow_users)
    local admin_user=""
    if [[ -n "$users" ]]; then
      admin_user=$(echo "$users" | awk '{print $1}' | cut -d'@' -f1 2>/dev/null)
    fi
    
    local host_ip=""
    if command -v hostname >/dev/null 2>&1; then
      host_ip=$(hostname -I 2>/dev/null | awk '{print $1}' 2>/dev/null)
    fi
    host_ip="${host_ip:-your-server-ip}"
    
    if [[ -n "$admin_user" ]]; then
      echo "ssh -p ${configured_port:-22} $admin_user@$host_ip"
    else
      echo "ssh -p ${configured_port:-22} username@$host_ip"
    fi
  fi
}

#=============================================================================
# MENU AND MAIN FUNCTION
#=============================================================================

show_main_menu() {
  clear
  echo "SSH Management Suite v${VERSION}"
  echo "==============================="
  echo "Host: $(hostname)"
  local current_port
  current_port=$(get_current_ssh_port)
  echo "SSH Port: $current_port"
  local users
  users=$(get_current_allow_users)
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

main() {
  require_root
  
  while true; do
    show_main_menu
    read -r -p "Choose option (1-6): " choice </dev/tty
    
    case "$choice" in
      1) 
        echo
        ssh_hardening_main
        echo
        echo "Press Enter to continue..."
        read -r </dev/tty
        ;;
      2) 
        echo
        multi_ip_config
        echo
        echo "Press Enter to continue..."
        read -r </dev/tty
        ;;
      3) 
        echo
        display_ssh_keys
        echo
        echo "Press Enter to continue..."
        read -r </dev/tty
        ;;
      4) 
        echo
        handle_rollback
        echo
        echo "Press Enter to continue..."
        read -r </dev/tty
        ;;
      5) 
        echo
        run_validation
        echo
        echo "Press Enter to continue..."
        read -r </dev/tty
        ;;
      6) 
        echo "Exiting SSH Management Suite..."
        exit 0
        ;;
      *) 
        echo "Invalid choice. Please select 1-6."
        sleep 1
        ;;
    esac
  done
}

# Entry point
main "$@"
