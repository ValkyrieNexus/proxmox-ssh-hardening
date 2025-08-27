#!/usr/bin/env bash
# SSH Management Suite - Complete with Multi-IP and Key Display
# v3.3 - Full Suite Version
set -Eeuo pipefail

# Global variables
VERSION="3.3"
NOW=""
REPORT=""
BACKUP_DIR=""
ROLLBACK=""
BACKUP_INDEX=""
CHANGED_INDEX=""
SSH_SERVICE=""

# Core helper functions - MUST BE DEFINED FIRST
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
      echo "Unable to read from terminal. Defaulting to 'n' for safety: $prompt"
      return 1
    }
    case "${ans:-}" in
      [Yy]) return 0 ;;
      [Nn]) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

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

random_pass() { 
  openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

validate_network() {
  local input="$1"
  
  # Check for CIDR notation
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip="${input%/*}"
    local cidr="${input#*/}"
    
    if [[ "$cidr" -gt 32 ]] || [[ "$cidr" -lt 1 ]]; then
      return 1
    fi
    
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
      if [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then
        return 1
      fi
    done
    return 0
    
  # Check for single IP
  elif [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -ra octets <<< "$input"
    for octet in "${octets[@]}"; do
      if [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then
        return 1
      fi
    done
    return 0
    
  # Check for hostname
  elif [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ ${#input} -le 253 ]]; then
    return 0
  else
    return 1
  fi
}

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
  
  if printf "%s" "$content" > "$temp_file"; then
    if mv "$temp_file" "$target"; then
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
  else
    rm -f "$temp_file"
    echo "ERROR: Failed to write temporary file for $target" | tee -a "$REPORT"
    return 1
  fi
}

# SSH Hardening Implementation
create_admin_user() {
  local admin_user="$1"
  
  if ASK "Create or ensure admin user '${admin_user}' with sudo?"; then
    if id "$admin_user" &>/dev/null; then
      echo "User '$admin_user' exists." | tee -a "$REPORT"
    else
      adduser --disabled-password --gecos "SSH Admin User" "$admin_user"
      echo "Created user '$admin_user'." | tee -a "$REPORT"
      echo "userdel -r '$admin_user'" >> "$ROLLBACK"
    fi
    
    usermod -aG sudo "$admin_user"
    echo "Granted sudo to '$admin_user'." | tee -a "$REPORT"
    
    local admin_pass="$(random_pass)"
    echo "$admin_user:$admin_pass" | chpasswd
    {
      echo "Admin User Credentials:"
      echo "Username: $admin_user"
      echo "Password: $admin_pass"
      echo "(Password login will be disabled after SSH key setup)"
      echo
    } >> "$REPORT"
  fi
}

generate_ssh_keys() {
  local admin_user="$1"
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  mkdir -p "$keys_dir"
  local pubkeys_out="${keys_dir}/ALL_PUBLIC_KEYS.txt"
  touch "$pubkeys_out"
  
  {
    echo "SSH Key Information:"
    echo "==================="
  } >> "$pubkeys_out"
  
  local has_keys=false
  
  if ASK "Generate encrypted Ed25519 key for '${admin_user}'?"; then
    local pass_ed="$(random_pass)"
    ssh-keygen -t ed25519 -a 100 -N "${pass_ed}" -C "${admin_user}@$(hostname)-ed25519-${NOW}" -f "${keys_dir}/${admin_user}_ed25519" >/dev/null 2>&1
    echo "Generated Ed25519 keypair: ${keys_dir}/${admin_user}_ed25519{,.pub}" | tee -a "$REPORT"
    
    {
      echo
      echo "### ${admin_user} Ed25519 Key"
      echo "Private key: ${keys_dir}/${admin_user}_ed25519"
      echo "Public key : ${keys_dir}/${admin_user}_ed25519.pub"
      echo "Passphrase : ${pass_ed}"
      echo "Public key content:"
      cat "${keys_dir}/${admin_user}_ed25519.pub"
      echo
    } >> "$pubkeys_out"
    
    has_keys=true
  fi
  
  if ASK "Also generate RSA-4096 key for compatibility?"; then
    local pass_rsa="$(random_pass)"
    ssh-keygen -t rsa -b 4096 -o -a 100 -N "${pass_rsa}" -C "${admin_user}@$(hostname)-rsa4096-${NOW}" -f "${keys_dir}/${admin_user}_rsa4096" >/dev/null 2>&1
    echo "Generated RSA-4096 keypair: ${keys_dir}/${admin_user}_rsa4096{,.pub}" | tee -a "$REPORT"
    
    {
      echo "### ${admin_user} RSA-4096 Key"
      echo "Private key: ${keys_dir}/${admin_user}_rsa4096"
      echo "Public key : ${keys_dir}/${admin_user}_rsa4096.pub" 
      echo "Passphrase : ${pass_rsa}"
      echo "Public key content:"
      cat "${keys_dir}/${admin_user}_rsa4096.pub"
      echo
    } >> "$pubkeys_out"
    
    has_keys=true
  fi
  
  if [[ "$has_keys" == "true" ]]; then
    echo "HAS_KEYS=true" >> "$BACKUP_DIR/_session_info.txt"
    echo "KEYS_DIR=${keys_dir}" >> "$BACKUP_DIR/_session_info.txt"
    echo "ADMIN_USER=${admin_user}" >> "$BACKUP_DIR/_session_info.txt"
  fi
}

install_ssh_keys() {
  local admin_user="$1"
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  
  if [[ ! -f "$BACKUP_DIR/_session_info.txt" ]] || ! grep -q "HAS_KEYS=true" "$BACKUP_DIR/_session_info.txt"; then
    return 0
  fi
  
  if ASK "Install generated public keys into ~$admin_user/.ssh/authorized_keys?"; then
    su - "$admin_user" -s /bin/bash -c 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys'
    
    local admin_auth_keys="/home/$admin_user/.ssh/authorized_keys"
    if [[ -s "$admin_auth_keys" ]]; then
      backup_file "$admin_auth_keys"
    fi
    
    if [[ -f "${keys_dir}/${admin_user}_ed25519.pub" ]]; then
      cat "${keys_dir}/${admin_user}_ed25519.pub" >> "$admin_auth_keys"
      echo "Installed Ed25519 public key" | tee -a "$REPORT"
    fi
    
    if [[ -f "${keys_dir}/${admin_user}_rsa4096.pub" ]]; then
      cat "${keys_dir}/${admin_user}_rsa4096.pub" >> "$admin_auth_keys"
      echo "Installed RSA-4096 public key" | tee -a "$REPORT"
    fi
    
    chown "$admin_user:$admin_user" "$admin_auth_keys"
    chmod 600 "$admin_auth_keys"
    chmod 700 "/home/$admin_user/.ssh"
    
    echo "$admin_auth_keys" >> "$CHANGED_INDEX"
  fi
}

apply_ssh_hardening() {
  local admin_user="$1"
  local ssh_port="$2"
  local allow_from="$3"
  
  if ASK "Apply SSH hardening configuration?"; then
    
    local allow_users=""
    if [[ -n "$allow_from" ]]; then
      allow_users="AllowUsers ${admin_user}@${allow_from}"
    else
      allow_users="AllowUsers ${admin_user}"
    fi
    
    local ssh_config="# SSH Hardening Configuration - Applied ${NOW}
# Original config backed up to ${BACKUP_DIR}

# Connection settings
Port ${ssh_port}
AddressFamily any
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# User restrictions  
${allow_users}
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30

# Protocol settings
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Encryption settings
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# Security settings
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
Compression no
TCPKeepAlive yes

# Logging
SyslogFacility AUTHPRIV
LogLevel INFO

# Banner
Banner none
PrintMotd yes
"

    install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
    
    {
      echo "SSH Configuration Changes:"
      echo "========================="
      echo "Port changed to: $ssh_port"
      echo "Root login: DISABLED"
      echo "Password authentication: DISABLED"
      echo "Public key authentication: ENABLED"
      echo "User restrictions: $allow_users"
      echo "Max auth tries: 3"
      echo "Connection timeout: 5 minutes"
      echo
    } >> "$REPORT"
  fi
}
# Restart SSH service (with socket activation fix)
restart_ssh_service() {
  local ssh_port="$1"
  
  if ASK "Restart SSH service to apply changes?"; then
    echo "Testing SSH configuration..." | tee -a "$REPORT"
    
    if ! sshd -t; then
      echo "ERROR: SSH configuration test failed!" | tee -a "$REPORT"
      return 1
    fi
    
    echo "SSH configuration test: PASSED" | tee -a "$REPORT"
    
    # Handle socket activation (critical fix)
    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
      echo "Disabling SSH socket activation..." | tee -a "$REPORT"
      systemctl stop ssh.socket >/dev/null 2>&1
      systemctl disable ssh.socket >/dev/null 2>&1  
      systemctl mask ssh.socket >/dev/null 2>&1
      echo "systemctl unmask ssh.socket; systemctl enable ssh.socket" >> "$ROLLBACK"
    fi
    
    echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
    
    systemctl stop "$SSH_SERVICE" >/dev/null 2>&1 || true
    sleep 1
    pkill -f sshd >/dev/null 2>&1 || true
    systemctl start "$SSH_SERVICE"
    echo "SSH service restarted" | tee -a "$REPORT"
    
    # Verify port binding
    local attempts=0
    while [[ $attempts -lt 10 ]]; do
      if netstat -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd || ss -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd; then
        echo "SSH is running on port $ssh_port" | tee -a "$REPORT"
        break
      fi
      ((attempts++))
      sleep 1
    done
    
    if [[ $attempts -eq 10 ]]; then
      echo "Attempting port fix..." | tee -a "$REPORT"
      sed -i '/^Port/d' /etc/ssh/sshd_config
      sed -i "1i Port $ssh_port" /etc/ssh/sshd_config
      sed -i '/UsePrivilegeSeparation/d' /etc/ssh/sshd_config
      
      if sshd -t; then
        systemctl restart "$SSH_SERVICE"
        sleep 2
        echo "Port configuration fixed" | tee -a "$REPORT"
      fi
    fi
  fi
}

# SSH Hardening Main Function
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
  
  {
    echo "SSH Hardening & Key Report - ${NOW}"
    echo "Host: $(hostname -f 2>/dev/null || hostname)"
    echo "IP: $(hostname -I | awk '{print $1}')"
    echo "Current SSH port: $(get_current_ssh_port)"
    echo "=================================="
  } > "$REPORT"
  
  {
    echo "#!/usr/bin/env bash"
    echo "set -Eeuo pipefail"
    echo "echo 'Rolling back SSH hardening changes...'"
  } > "$ROLLBACK"
  chmod +x "$ROLLBACK"
  
  read -r -p "Admin username (default: admin): " ADMIN </dev/tty || ADMIN="admin"
  ADMIN="${ADMIN:-admin}"
  
  read -r -p "SSH port (default: 2222): " SSH_PORT </dev/tty || SSH_PORT="2222"
  SSH_PORT="${SSH_PORT:-2222}"
  
  read -r -p "Allow from (CIDR/IP, empty = any): " ALLOW_FROM </dev/tty || ALLOW_FROM=""
  
  create_admin_user "$ADMIN"
  generate_ssh_keys "$ADMIN"
  install_ssh_keys "$ADMIN"
  apply_ssh_hardening "$ADMIN" "$SSH_PORT" "$ALLOW_FROM"
  restart_ssh_service "$SSH_PORT"
  
  {
    echo
    echo "Connection Test Command:"
    local keys_dir="/root/ssh-generated-keys-${NOW}"
    if [[ -f "${keys_dir}/${ADMIN}_ed25519" ]]; then
      echo "ssh -i ${keys_dir}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')"
    fi
    echo
    echo "Rollback: $ROLLBACK"
    echo "Keys: $keys_dir"
  } >> "$REPORT"
  
  echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
  
  chmod 600 /root/ssh-generated-keys-${NOW}/* 2>/dev/null || true
  chmod 644 /root/ssh-generated-keys-${NOW}/*.pub 2>/dev/null || true
  
  echo
  echo "SSH Hardening Complete!"
  echo "Report: $REPORT"
  echo "CRITICAL: Test connection before closing session!"
}

# Multi-IP Configuration
multi_ip_config() {
  NOW="$(timestamp)"
  REPORT="/root/ssh-multi-ip-config-${NOW}.txt"
  SSH_SERVICE="$(detect_ssh_service)"
  
  echo "SSH Multi-IP Configuration"
  echo "=========================="
  
  local current_port=$(get_current_ssh_port)
  local current_allow=$(get_current_allow_users)
  
  echo "Current SSH port: $current_port"
  echo "Current AllowUsers: ${current_allow:-"(not set)"}"
  
  while true; do
    read -r -p "Enter SSH username: " username </dev/tty
    if [[ -n "$username" ]] && [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      if id "$username" &>/dev/null; then
        break
      else
        echo "WARNING: User '$username' does not exist."
        if ASK "Continue anyway?"; then
          break
        fi
      fi
    else
      echo "Invalid username format."
    fi
  done
  
  echo
  echo "Enter networks (empty line to finish):"
  echo "Examples: 10.0.0.0/8, 192.168.1.0/24, 203.0.113.45"
  
  local networks=()
  while true; do
    read -r -p "Network/IP: " network </dev/tty
    if [[ -z "$network" ]]; then
      break
    fi
    if validate_network "$network"; then
      networks+=("$network")
      echo "Added: $network"
    else
      echo "Invalid format: $network"
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
  
  echo
  echo "Configuration:"
  echo "Username: $username"
  for net in "${networks[@]}"; do
    echo "  - $net"  
  done
  echo "AllowUsers: $allow_users_line"
  
  if ! ASK "Apply this configuration?"; then
    return 1
  fi
  
  local backup_file="/root/sshd_config.backup.${NOW}"
  cp /etc/ssh/sshd_config "$backup_file"
  
  local temp_config="/tmp/sshd_config.tmp.$$"
  grep -v "^AllowUsers" /etc/ssh/sshd_config > "$temp_config"
  echo "$allow_users_line" >> "$temp_config"
  
  if sshd -t -f "$temp_config"; then
    cp "$temp_config" /etc/ssh/sshd_config
    systemctl restart "$SSH_SERVICE"
    rm -f "$temp_config"
    
    {
      echo "Multi-IP Configuration - $NOW"
      echo "Username: $username"  
      echo "Networks: ${networks[*]}"
      echo "Backup: $backup_file"
      echo "Rollback: sudo cp $backup_file /etc/ssh/sshd_config && sudo systemctl restart $SSH_SERVICE"
    } > "$REPORT"
    
    echo "SUCCESS: Multi-IP configuration applied!"
    echo "Report: $REPORT"
  else
    echo "Configuration test failed!"
    rm -f "$temp_config"
    return 1
  fi
}

# Display SSH Keys and Passphrases
display_ssh_keys() {
  echo "SSH Keys and Passphrases"
  echo "========================"
  
  local key_sessions=()
  for keys_dir in /root/ssh-generated-keys-*; do
    if [[ -d "$keys_dir" ]]; then
      local timestamp=$(basename "$keys_dir" | sed 's/ssh-generated-keys-//')
      key_sessions+=("$timestamp")
    fi
  done
  
  if [[ ${#key_sessions[@]} -eq 0 ]]; then
    echo "No SSH key sessions found."
    return 0
  fi
  
  echo "Available key sessions:"
  for i in "${!key_sessions[@]}"; do
    echo "$((i+1)). Session: ${key_sessions[$i]}"
  done
  
  read -r -p "Select session (1-${#key_sessions[@]}): " session_choice </dev/tty
  
  if [[ "$session_choice" =~ ^[0-9]+$ ]] && [[ "$session_choice" -ge 1 ]] && [[ "$session_choice" -le ${#key_sessions[@]} ]]; then
    local selected_session="${key_sessions[$((session_choice-1))]}"
    local keys_dir="/root/ssh-generated-keys-$selected_session"
    local key_info_file="$keys_dir/ALL_PUBLIC_KEYS.txt"
    
    if [[ -f "$key_info_file" ]]; then
      echo
      echo "SSH Key Information for Session: $selected_session"
      echo "=================================================="
      cat "$key_info_file"
      echo
      echo "Private key files location:"
      find "$keys_dir" -name "*_ed25519" -o -name "*_rsa4096" 2>/dev/null | while read -r key_file; do
        echo "  $key_file"
      done
      echo
    else
      echo "Key information file not found for session $selected_session"
      echo "Available files in $keys_dir:"
      ls -la "$keys_dir" 2>/dev/null || echo "Directory not accessible"
    fi
  else
    echo "Invalid session number."
  fi
}

# Rollback Management  
handle_rollback() {
  echo "SSH Session Rollback"
  echo "===================="
  
  local sessions=()
  for report in /root/ssh-hardening-report-*; do
    if [[ -f "$report" ]]; then
      local timestamp=$(basename "$report" | sed 's/ssh-hardening-report-//' | sed 's/.txt//')
      sessions+=("$timestamp")
    fi
  done
  
  # Add multi-IP sessions
  for report in /root/ssh-multi-ip-config-*; do
    if [[ -f "$report" ]]; then
      local timestamp=$(basename "$report" | sed 's/ssh-multi-ip-config-//' | sed 's/.txt//')
      sessions+=("$timestamp")
    fi
  done
  
  if [[ ${#sessions[@]} -eq 0 ]]; then
    echo "No rollback sessions found."
    return 0
  fi
  
  echo "Available sessions:"
  for i in "${!sessions[@]}"; do
    local session="${sessions[$i]}"
    echo -n "$((i+1)). Session: $session"
    
    if [[ -f "/root/ssh-hardening-report-$session.txt" ]]; then
      echo " (SSH Hardening)"
    elif [[ -f "/root/ssh-multi-ip-config-$session.txt" ]]; then
      echo " (Multi-IP Config)"  
    else
      echo " (Unknown)"
    fi
  done
  
  read -r -p "Select session to rollback (1-${#sessions[@]}): " session_choice </dev/tty
  
  if [[ "$session_choice" =~ ^[0-9]+$ ]] && [[ "$session_choice" -ge 1 ]] && [[ "$session_choice" -le ${#sessions[@]} ]]; then
    local selected_session="${sessions[$((session_choice-1))]}"
    
    echo
    echo "Session details:"
    if [[ -f "/root/ssh-hardening-report-$selected_session.txt" ]]; then
      head -10 "/root/ssh-hardening-report-$selected_session.txt"
    elif [[ -f "/root/ssh-multi-ip-config-$selected_session.txt" ]]; then
      cat "/root/ssh-multi-ip-config-$selected_session.txt"
    fi
    
    if ASK "Proceed with rollback?"; then
      local rollback_script="/root/ssh-hardening-rollback-$selected_session.sh"
      
      if [[ -x "$rollback_script" ]]; then
        echo "Executing rollback script..."
        "$rollback_script"
        echo "Rollback completed."
      else
        # Manual rollback
        local backup_file=""
        for location in "/root/ssh-hardening-backups-$selected_session" "/root"; do
          for file in "$location"/sshd_config*.bak "$location/sshd_config.backup.$selected_session"; do
            if [[ -f "$file" ]]; then
              backup_file="$file"
              break 2
            fi
          done
        done
        
        if [[ -f "$backup_file" ]]; then
          cp "$backup_file" /etc/ssh/sshd_config
          systemctl unmask ssh.socket 2>/dev/null || true
          systemctl restart ssh
          echo "Configuration restored from: $backup_file"
        else
          echo "No backup file found for session $selected_session"
        fi
      fi
    fi
  else
    echo "Invalid session number."
  fi
}

# Validation
run_validation() {
  echo "SSH Configuration Validation"
  echo "============================"
  
  local tests_passed=0
  local tests_total=7
  
  # Test SSH config syntax
  if sshd -t 2>/dev/null; then
    echo "[PASS] SSH configuration syntax valid"
    ((tests_passed++))
  else
    echo "[FAIL] SSH configuration has errors"
  fi
  
  # Test SSH service
  if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
    echo "[PASS] SSH service is running"
    ((tests_passed++))
  else
    echo "[FAIL] SSH service not running"
  fi
  
  # Test SSH port
  local current_port=$(get_current_ssh_port)
  if netstat -tlnp 2>/dev/null | grep ":${current_port} " | grep -q sshd || ss -tlnp 2>/dev/null | grep ":${current_port} " | grep -q sshd; then
    echo "[PASS] SSH listening on port $current_port"
    ((tests_passed++))
  else
    echo "[FAIL] SSH not listening on port $current_port"
  fi
  
  # Test security settings
  if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Root login disabled"
    ((tests_passed++))
  else
    echo "[WARN] Root login may be enabled"
  fi
  
  if grep -q "^PasswordAuthentication no" /
# Continue validation function
  if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Password authentication disabled"
    ((tests_passed++))
  else
    echo "[WARN] Password authentication may be enabled"
  fi
  
  if grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo "[PASS] Public key authentication enabled"
    ((tests_passed++))
  else
    echo "[WARN] Public key authentication not explicitly set"
  fi
  
  if grep -q "^AllowUsers" /etc/ssh/sshd_config 2>/dev/null; then
    local allowed_users=$(grep "^AllowUsers" /etc/ssh/sshd_config | sed 's/^AllowUsers\s*//')
    echo "[PASS] User access restricted: $allowed_users"
    ((tests_passed++))
  else
    echo "[WARN] No user access restrictions found"
  fi
  
  echo
  echo "Validation Summary: $tests_passed/$tests_total tests passed"
  
  if [[ $tests_passed -eq $tests_total ]]; then
    echo "[PASS] SSH hardening appears successful"
  else
    echo "[WARN] Some security settings may need attention"
  fi
}

# Main Menu
show_main_menu() {
  clear
  echo "SSH Management Suite v${VERSION}"
  echo "==============================="
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "Current SSH Port: $(get_current_ssh_port)"
  
  local allow_users=$(get_current_allow_users)
  if [[ -n "$allow_users" ]]; then
    echo "AllowUsers: $allow_users"
  fi
  
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
    read -r -p "Choose an option (1-6): " choice </dev/tty
    
    case "$choice" in
      1)
        echo
        echo "Starting SSH Hardening Process..."
        echo "================================"
        ssh_hardening_main
        echo
        read -r -p "Press Enter to continue..." </dev/tty
        ;;
      2)
        echo
        echo "Starting Multi-IP Configuration..."
        echo "================================="
        multi_ip_config
        echo
        read -r -p "Press Enter to continue..." </dev/tty
        ;;
      3)
        echo
        display_ssh_keys
        echo
        read -r -p "Press Enter to continue..." </dev/tty
        ;;
      4)
        echo
        handle_rollback
        echo
        read -r -p "Press Enter to continue..." </dev/tty
        ;;
      5)
        echo
        run_validation
        echo
        read -r -p "Press Enter to continue..." </dev/tty
        ;;
      6)
        echo "Exiting SSH Management Suite..."
        exit 0
        ;;
      *)
        echo "Invalid option. Please choose 1-6."
        sleep 2
        ;;
    esac
  done
}

# Run main function
main "$@"
