#!/usr/bin/env bash
# SSH Management Suite - Complete Single File Version
# Includes hardening, multi-IP, key display, rollback, and validation
# v3.3

set -Eeuo pipefail

VERSION="3.3"
NOW=""
REPORT=""
BACKUP_DIR=""
ROLLBACK=""
BACKUP_INDEX=""
CHANGED_INDEX=""
SSH_SERVICE=""

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
  
  read -r -p "Admin username (default: admin): " ADMIN </dev/tty || ADMIN="admin"
  ADMIN="${ADMIN:-admin}"
  
  read -r -p "SSH port (default: 2222): " SSH_PORT </dev/tty || SSH_PORT="2222"
  SSH_PORT="${SSH_PORT:-2222}"
  
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
  
  # Restart SSH service
  if ASK "Restart SSH service to apply changes?"; then
    if sshd -t; then
      echo "SSH config test: PASSED" | tee -a "$REPORT"
      
      # Handle socket activation
      if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
        systemctl stop ssh.socket >/dev/null 2>&1
        systemctl disable ssh.socket >/dev/null 2>&1
        systemctl mask ssh.socket >/dev/null 2>&1
        echo "systemctl unmask ssh.socket" >> "$ROLLBACK"
      fi
      
      echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
      
      systemctl stop "$SSH_SERVICE" >/dev/null 2>&1 || true
      sleep 1
      pkill -f sshd >/dev/null 2>&1 || true
      systemctl start "$SSH_SERVICE"
      
      # Verify port
      local attempts=0
      while [[ $attempts -lt 10 ]]; do
        if netstat -tlnp 2>/dev/null | grep ":${SSH_PORT} " | grep -q sshd || ss -tlnp 2>/dev/null | grep ":${SSH_PORT} " | grep -q sshd; then
          echo "SSH is running on port $SSH_PORT" | tee -a "$REPORT"
          break
        fi
        ((attempts++))
        sleep 1
      done
      
      if [[ $attempts -eq 10 ]]; then
        sed -i '/^Port/d' /etc/ssh/sshd_config
        sed -i "1i Port $SSH_PORT" /etc/ssh/sshd_config
        systemctl restart "$SSH_SERVICE"
      fi
    else
      echo "SSH config test failed!" | tee -a "$REPORT"
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

multi_ip_config() {
  local current_port=$(get_current_ssh_port)
  echo "Multi-IP Configuration (Current port: $current_port)"
  
  while true; do
    read -r -p "SSH username: " username </dev/tty
    if [[ -n "$username" ]] && [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      if id "$username" &>/dev/null; then
        break
      else
        if ASK "User '$username' does not exist. Continue?"; then break; fi
      fi
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
      echo "Invalid: $network"
    fi
  done
  
  [[ ${#networks[@]} -eq 0 ]] && { echo "No networks specified."; return 1; }
  
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
    systemctl restart "$(detect_ssh_service)"
    rm -f "$temp_config"
    echo "Multi-IP configuration applied! Backup: $backup_file"
  else
    echo "Configuration test failed!"
    rm -f "$temp_config"
    return 1
  fi
}

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
      find "$keys_dir" -name "*_ed25519" -o -name "*_rsa4096" 2>/dev/null || echo "No private keys found"
    else
      echo "Key information not found for session $session"
    fi
  fi
}

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
      "$rollback_script"
    else
      # Manual rollback
      for backup in "/root/ssh-hardening-backups-$session"/sshd_config*.bak "/root/sshd_config.backup.$session"; do
        if [[ -f "$backup" ]]; then
          cp "$backup" /etc/ssh/sshd_config
          systemctl restart "$(detect_ssh_service)"
          echo "Restored from $backup"
          return
        fi
      done
      echo "No backup found for $session"
    fi
  fi
}

run_validation() {
  echo "SSH Configuration Validation"
  echo "============================"
  
  local tests_passed=0
  local tests_total=6
  
  sshd -t 2>/dev/null && { echo "[PASS] SSH config valid"; ((tests_passed++)); } || echo "[FAIL] SSH config invalid"
  
  (systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1) && { echo "[PASS] SSH service running"; ((tests_passed++)); } || echo "[FAIL] SSH service not running"
  
  local port=$(get_current_ssh_port)
  (netstat -tlnp 2>/dev/null | grep ":$port " | grep -q sshd || ss -tlnp 2>/dev/null | grep ":$port " | grep -q sshd) && { echo "[PASS] SSH listening on $port"; ((tests_passed++)); } || echo "[FAIL] SSH not on $port"
  
  grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null && { echo "[PASS] Root login disabled"; ((tests_passed++)); } || echo "[WARN] Root login enabled"
  
  grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null && { echo "[PASS] Password auth disabled"; ((tests_passed++)); } || echo "[WARN] Password auth enabled"
  
  grep -q "^AllowUsers" /etc/ssh/sshd_config 2>/dev/null && { echo "[PASS] User restrictions active"; ((tests_passed++)); } || echo "[WARN] No user restrictions"
  
  echo "Validation: $tests_passed/$tests_total tests passed"
}

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
      *) echo "Invalid choice"; sleep 1 ;;
    esac
  done
}

main "$@"