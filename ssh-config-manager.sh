#!/usr/bin/env bash
# ==========================================
# DEPRECATED: This script is deprecated
# ==========================================
# This functionality is now included in the
# SSH Management Suite (Option 2: Configure multi-IP access)
#
# Use: curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash
# ==========================================

echo "DEPRECATED: This script has been replaced by the SSH Management Suite"
echo "Run the suite and choose Option 2 for multi-IP configuration"
echo
echo "New command:"
echo "curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash"
echo
read -p "Continue anyway? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Original script content follows...
#!/usr/bin/env bash
# SSH Configuration Manager
# Modify SSH hardening settings after initial setup
# v1.0

set -Eeuo pipefail

# ---------- Helpers ----------
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
  mkdir -p "$(dirname "$target")"
  if [[ -e "$target" ]]; then
    backup_file "$target"
  fi
  printf "%s" "$content" > "$target"
  echo "Updated $target" | tee -a "$REPORT"
  echo "$target" >> "$CHANGED_INDEX"
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

validate_ip_or_cidr() {
  local input="$1"
  
  # Check for CIDR notation
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip="${input%/*}"
    local cidr="${input#*/}"
    
    # Validate CIDR range
    if [[ "$cidr" -gt 32 ]] || [[ "$cidr" -lt 1 ]]; then
      return 1
    fi
    
    # Validate IP octets
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
    
  # Check for hostname (basic validation)
  elif [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ ${#input} -le 253 ]]; then
    return 0
  else
    return 1
  fi
}

# ---------- Init ----------
require_root
NOW="$(timestamp)"
REPORT="/root/ssh-config-changes-${NOW}.txt"
BACKUP_DIR="/root/ssh-config-backups-${NOW}"
ROLLBACK="/root/ssh-config-rollback-${NOW}.sh"
BACKUP_INDEX="${BACKUP_DIR}/_backup-index.txt"
CHANGED_INDEX="${BACKUP_DIR}/_changed-files.txt"
mkdir -p "$BACKUP_DIR"
touch "$BACKUP_INDEX" "$CHANGED_INDEX"
SSH_SERVICE="$(detect_ssh_service)"
CURRENT_SSH_PORT="$(get_current_ssh_port)"
CURRENT_ALLOW_USERS="$(get_current_allow_users)"

{
  echo "SSH Configuration Changes Report - ${NOW}"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "IP: $(hostname -I | awk '{print $1}')"
  echo "Current SSH port: ${CURRENT_SSH_PORT}"
  echo "Current AllowUsers: ${CURRENT_ALLOW_USERS:-"(not set)"}"
  echo "Backups dir: ${BACKUP_DIR}"
  echo "SSH service: ${SSH_SERVICE}"
  echo "=================================="
  echo
} > "$REPORT"

# Initialize rollback script
{
  echo "#!/usr/bin/env bash"
  echo "# SSH Configuration Rollback Script - ${NOW}"
  echo "set -Eeuo pipefail"
  echo
  echo "echo 'Rolling back SSH configuration changes...'"
  echo
} > "$ROLLBACK"
chmod +x "$ROLLBACK"

echo "SSH Configuration Manager v1.0"
echo "==============================="
echo "Current SSH port: $CURRENT_SSH_PORT"
echo "Current AllowUsers: ${CURRENT_ALLOW_USERS:-"(not set)"}"
echo

# ---------- Configuration Menu ----------
show_menu() {
  echo
  echo "What would you like to modify?"
  echo "1) Change SSH port"
  echo "2) Modify user access (AllowUsers)"
  echo "3) Add/remove authorized SSH keys"
  echo "4) Change SSH security settings"
  echo "5) View current configuration"
  echo "6) Exit"
  echo
}

# ---------- Change SSH Port ----------
change_ssh_port() {
  echo
  echo "Current SSH port: $CURRENT_SSH_PORT"
  read -r -p "Enter new SSH port (1024-65535): " NEW_PORT </dev/tty
  
  if [[ ! "$NEW_PORT" =~ ^[0-9]+$ ]] || [[ "$NEW_PORT" -lt 1024 ]] || [[ "$NEW_PORT" -gt 65535 ]]; then
    echo "ERROR: Invalid port number. Must be between 1024-65535."
    return 1
  fi
  
  if [[ "$NEW_PORT" == "$CURRENT_SSH_PORT" ]]; then
    echo "Port is already set to $NEW_PORT. No changes needed."
    return 0
  fi
  
  echo "Changing SSH port from $CURRENT_SSH_PORT to $NEW_PORT..."
  
  # Read current config and update port
  local ssh_config
  ssh_config=$(cat /etc/ssh/sshd_config)
  ssh_config=$(echo "$ssh_config" | sed "s/^Port .*/Port $NEW_PORT/")
  
  install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
  
  {
    echo "SSH Port Changes:"
    echo "=================="
    echo "Old port: $CURRENT_SSH_PORT"
    echo "New port: $NEW_PORT"
    echo "Change time: $(date)"
    echo
  } >> "$REPORT"
  
  # Add rollback command
  echo "sed -i 's/^Port .*/Port $CURRENT_SSH_PORT/' /etc/ssh/sshd_config" >> "$ROLLBACK"
  
  CURRENT_SSH_PORT="$NEW_PORT"
  return 0
}

# ---------- Modify User Access ----------
modify_user_access() {
  echo
  echo "Current AllowUsers setting: ${CURRENT_ALLOW_USERS:-"(not set - all users allowed)"}"
  echo
  echo "User access configuration options:"
  echo "1) Set single user from any IP: user"
  echo "2) Set user from specific IP: user@192.168.1.100"
  echo "3) Set user from subnet: user@192.168.1.0/24"
  echo "4) Set multiple users/IPs (advanced)"
  echo "5) Remove restrictions (allow all users)"
  echo
  
  read -r -p "Choose option (1-5): " choice </dev/tty
  
  case "$choice" in
    1)
      read -r -p "Enter username: " username </dev/tty
      NEW_ALLOW_USERS="AllowUsers $username"
      ;;
    2)
      read -r -p "Enter username: " username </dev/tty
      read -r -p "Enter IP address: " ip </dev/tty
      if ! validate_ip_or_cidr "$ip"; then
        echo "ERROR: Invalid IP address format."
        return 1
      fi
      NEW_ALLOW_USERS="AllowUsers $username@$ip"
      ;;
    3)
      read -r -p "Enter username: " username </dev/tty
      read -r -p "Enter subnet (e.g., 192.168.1.0/24): " subnet </dev/tty
      if ! validate_ip_or_cidr "$subnet"; then
        echo "ERROR: Invalid subnet format."
        return 1
      fi
      NEW_ALLOW_USERS="AllowUsers $username@$subnet"
      ;;
    4)
      configure_multiple_access
      return $?
      ;;
    5)
      NEW_ALLOW_USERS=""
      ;;
    *)
      echo "Invalid choice."
      return 1
      ;;
  esac
  
  # Apply the changes
  apply_allow_users_change "$NEW_ALLOW_USERS"
}

# ---------- Configure Multiple Access (Advanced) ----------
configure_multiple_access() {
  echo
  echo "Advanced Multiple Access Configuration"
  echo "====================================="
  echo "You can configure access for one user from multiple locations."
  echo "For your use case (MacBook via Teleport at office + home subnets):"
  echo
  
  read -r -p "Enter username: " username </dev/tty
  
  echo
  echo "Now enter your access sources (press Enter after each, empty line to finish):"
  echo "Examples:"
  echo "  192.168.1.0/24     (home subnet 1)"
  echo "  10.0.0.0/16        (office/teleport network)"
  echo "  192.168.50.0/24    (home subnet 2)"
  echo "  specific.hostname.com"
  echo
  
  local sources=()
  local source
  while true; do
    read -r -p "Enter IP/CIDR/hostname (empty to finish): " source </dev/tty
    if [[ -z "$source" ]]; then
      break
    fi
    if validate_ip_or_cidr "$source"; then
      sources+=("$username@$source")
      echo "Added: $username@$source"
    else
      echo "Invalid format: $source (skipping)"
    fi
  done
  
  if [[ ${#sources[@]} -eq 0 ]]; then
    echo "No valid sources entered."
    return 1
  fi
  
  # Join sources with spaces
  local allow_users_line="AllowUsers"
  for src in "${sources[@]}"; do
    allow_users_line="$allow_users_line $src"
  done
  
  echo
  echo "Proposed AllowUsers configuration:"
  echo "$allow_users_line"
  echo
  
  if ASK "Apply this configuration?"; then
    NEW_ALLOW_USERS="$allow_users_line"
    apply_allow_users_change "$NEW_ALLOW_USERS"
    return $?
  else
    echo "Configuration cancelled."
    return 1
  fi
}

# ---------- Apply AllowUsers Changes ----------
apply_allow_users_change() {
  local new_setting="$1"
  local temp_config="/tmp/sshd_config.tmp.$"
  
  # Read current config and remove existing AllowUsers lines
  if ! grep -v "^AllowUsers" /etc/ssh/sshd_config > "$temp_config"; then
    echo "ERROR: Failed to process SSH config file"
    rm -f "$temp_config"
    return 1
  fi
  
  # Add new AllowUsers line if specified
  if [[ -n "$new_setting" ]]; then
    echo "$new_setting" >> "$temp_config"
  fi
  
  # Validate the new configuration
  if ! sshd -t -f "$temp_config"; then
    echo "ERROR: New SSH configuration would be invalid"
    rm -f "$temp_config"
    return 1
  fi
  
  # Apply the configuration
  if ! install_file_with_backup "/etc/ssh/sshd_config" "$(cat "$temp_config")"; then
    echo "ERROR: Failed to update SSH configuration"
    rm -f "$temp_config"
    return 1
  fi
  
  rm -f "$temp_config"
  
  {
    echo "AllowUsers Changes:"
    echo "==================="
    echo "Old setting: ${CURRENT_ALLOW_USERS:-"(not set)"}"
    echo "New setting: ${new_setting:-"(not set - all users allowed)"}"
    echo "Change time: $(date)"
    echo
  } >> "$REPORT"
  
  # Add rollback command
  local rollback_cmd
  if [[ -n "$CURRENT_ALLOW_USERS" ]]; then
    rollback_cmd="sed -i '/^AllowUsers/d' /etc/ssh/sshd_config && echo 'AllowUsers $CURRENT_ALLOW_USERS' >> /etc/ssh/sshd_config"
  else
    rollback_cmd="sed -i '/^AllowUsers/d' /etc/ssh/sshd_config"
  fi
  echo "$rollback_cmd" >> "$ROLLBACK"
  
  CURRENT_ALLOW_USERS="${new_setting#AllowUsers }"
  echo "User access configuration updated successfully."
  return 0
}

# ---------- Manage SSH Keys ----------
manage_ssh_keys() {
  echo
  echo "SSH Key Management"
  echo "=================="
  echo "1) Add new SSH key to user"
  echo "2) Remove SSH key from user"
  echo "3) List current SSH keys for user"
  echo "4) Back to main menu"
  echo
  
  read -r -p "Choose option (1-4): " choice </dev/tty
  
  case "$choice" in
    1) add_ssh_key ;;
    2) remove_ssh_key ;;
    3) list_ssh_keys ;;
    4) return 0 ;;
    *) echo "Invalid choice." ;;
  esac
}

add_ssh_key() {
  read -r -p "Enter username: " username </dev/tty
  
  if ! id "$username" &>/dev/null; then
    echo "ERROR: User '$username' does not exist."
    return 1
  fi
  
  echo "Enter the public key (paste the entire key):"
  read -r public_key </dev/tty
  
  if [[ ! "$public_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-) ]]; then
    echo "ERROR: Invalid SSH public key format."
    return 1
  fi
  
  local auth_keys="/home/$username/.ssh/authorized_keys"
  
  # Create .ssh directory if it doesn't exist
  su - "$username" -s /bin/bash -c 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys'
  
  # Backup current authorized_keys
  if [[ -e "$auth_keys" ]]; then
    backup_file "$auth_keys"
  fi
  
  # Add the key
  echo "$public_key" >> "$auth_keys"
  chown "$username:$username" "$auth_keys"
  chmod 600 "$auth_keys"
  
  {
    echo "SSH Key Addition:"
    echo "=================="
    echo "User: $username"
    echo "Key: ${public_key:0:50}..."
    echo "Added: $(date)"
    echo
  } >> "$REPORT"
  
  echo "SSH key added successfully for user '$username'."
}

remove_ssh_key() {
  read -r -p "Enter username: " username </dev/tty
  
  local auth_keys="/home/$username/.ssh/authorized_keys"
  
  if [[ ! -f "$auth_keys" ]]; then
    echo "ERROR: No authorized_keys file found for user '$username'."
    return 1
  fi
  
  echo "Current SSH keys for $username:"
  nl -nln "$auth_keys"
  echo
  
  read -r -p "Enter line number to remove: " line_num </dev/tty
  
  if ! [[ "$line_num" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Invalid line number."
    return 1
  fi
  
  local total_lines=$(wc -l < "$auth_keys")
  if [[ "$line_num" -gt "$total_lines" ]] || [[ "$line_num" -lt 1 ]]; then
    echo "ERROR: Line number out of range."
    return 1
  fi
  
  backup_file "$auth_keys"
  
  # Remove the specified line
  sed -i "${line_num}d" "$auth_keys"
  
  {
    echo "SSH Key Removal:"
    echo "================"
    echo "User: $username"
    echo "Removed line: $line_num"
    echo "Removed: $(date)"
    echo
  } >> "$REPORT"
  
  echo "SSH key removed successfully."
}

list_ssh_keys() {
  read -r -p "Enter username: " username </dev/tty
  
  local auth_keys="/home/$username/.ssh/authorized_keys"
  
  if [[ ! -f "$auth_keys" ]]; then
    echo "No authorized_keys file found for user '$username'."
    return 0
  fi
  
  echo
  echo "SSH keys for user '$username':"
  echo "=============================="
  nl -nln "$auth_keys"
  echo
}

# ---------- Security Settings ----------
modify_security_settings() {
  echo
  echo "SSH Security Settings"
  echo "===================="
  echo "1) Change MaxAuthTries (login attempt limit)"
  echo "2) Change ClientAliveInterval (timeout)"
  echo "3) Toggle X11Forwarding"
  echo "4) Toggle AllowAgentForwarding"
  echo "5) Back to main menu"
  echo
  
  read -r -p "Choose option (1-5): " choice </dev/tty
  
  case "$choice" in
    1) change_max_auth_tries ;;
    2) change_alive_interval ;;
    3) toggle_x11_forwarding ;;
    4) toggle_agent_forwarding ;;
    5) return 0 ;;
    *) echo "Invalid choice." ;;
  esac
}

change_max_auth_tries() {
  local current=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}' || echo "6")
  echo "Current MaxAuthTries: $current"
  read -r -p "Enter new MaxAuthTries (1-10): " new_tries </dev/tty
  
  if [[ ! "$new_tries" =~ ^[0-9]+$ ]] || [[ "$new_tries" -lt 1 ]] || [[ "$new_tries" -gt 10 ]]; then
    echo "ERROR: Invalid value. Must be between 1-10."
    return 1
  fi
  
  local ssh_config
  ssh_config=$(cat /etc/ssh/sshd_config)
  ssh_config=$(echo "$ssh_config" | sed "s/^MaxAuthTries .*/MaxAuthTries $new_tries/")
  
  install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
  
  echo "MaxAuthTries updated to $new_tries."
}

change_alive_interval() {
  local current=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}' || echo "300")
  echo "Current ClientAliveInterval: $current seconds"
  read -r -p "Enter new timeout in seconds (60-3600): " new_interval </dev/tty
  
  if [[ ! "$new_interval" =~ ^[0-9]+$ ]] || [[ "$new_interval" -lt 60 ]] || [[ "$new_interval" -gt 3600 ]]; then
    echo "ERROR: Invalid value. Must be between 60-3600 seconds."
    return 1
  fi
  
  local ssh_config
  ssh_config=$(cat /etc/ssh/sshd_config)
  ssh_config=$(echo "$ssh_config" | sed "s/^ClientAliveInterval .*/ClientAliveInterval $new_interval/")
  
  install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
  
  echo "ClientAliveInterval updated to $new_interval seconds."
}

toggle_x11_forwarding() {
  local current=$(grep "^X11Forwarding" /etc/ssh/sshd_config | awk '{print $2}' || echo "no")
  local new_value
  
  if [[ "$current" == "yes" ]]; then
    new_value="no"
  else
    new_value="yes"
  fi
  
  echo "Current X11Forwarding: $current"
  if ASK "Change X11Forwarding to $new_value?"; then
    local ssh_config
    ssh_config=$(cat /etc/ssh/sshd_config)
    ssh_config=$(echo "$ssh_config" | sed "s/^X11Forwarding .*/X11Forwarding $new_value/")
    
    install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
    
    echo "X11Forwarding updated to $new_value."
  fi
}

toggle_agent_forwarding() {
  local current=$(grep "^AllowAgentForwarding" /etc/ssh/sshd_config | awk '{print $2}' || echo "no")
  local new_value
  
  if [[ "$current" == "yes" ]]; then
    new_value="no"
  else
    new_value="yes"
  fi
  
  echo "Current AllowAgentForwarding: $current"
  if ASK "Change AllowAgentForwarding to $new_value?"; then
    local ssh_config
    ssh_config=$(cat /etc/ssh/sshd_config)
    ssh_config=$(echo "$ssh_config" | sed "s/^AllowAgentForwarding .*/AllowAgentForwarding $new_value/")
    
    install_file_with_backup "/etc/ssh/sshd_config" "$ssh_config"
    
    echo "AllowAgentForwarding updated to $new_value."
  fi
}

# ---------- View Configuration ----------
view_current_config() {
  echo
  echo "Current SSH Configuration"
  echo "========================"
  echo "SSH Port: $(get_current_ssh_port)"
  echo "AllowUsers: $(get_current_allow_users || echo "(not set - all users allowed)")"
  echo "PermitRootLogin: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "PasswordAuthentication: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "PubkeyAuthentication: $(grep "^PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "MaxAuthTries: $(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "ClientAliveInterval: $(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "X11Forwarding: $(grep "^X11Forwarding" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo "AllowAgentForwarding: $(grep "^AllowAgentForwarding" /etc/ssh/sshd_config | awk '{print $2}' || echo "(default)")"
  echo
}

# ---------- Main Loop ----------
main() {
  while true; do
    show_menu
    read -r -p "Enter your choice (1-6): " choice </dev/tty
    
    case "$choice" in
      1) change_ssh_port ;;
      2) modify_user_access ;;
      3) manage_ssh_keys ;;
      4) modify_security_settings ;;
      5) view_current_config ;;
      6) break ;;
      *) echo "Invalid choice. Please try again." ;;
    esac
    
    if [[ "$choice" =~ ^[1-4]$ ]]; then
      echo
      if ASK "Test SSH configuration and restart service?"; then
        test_and_restart_ssh
      fi
    fi
  done
  
  # Final report
  finalize_report
}

# ---------- Test and Restart SSH ----------
test_and_restart_ssh() {
  echo "Testing SSH configuration..." | tee -a "$REPORT"
  
  if ! sshd -t; then
    echo "ERROR: SSH configuration test failed!" | tee -a "$REPORT"
    echo "Not restarting SSH service. Please check configuration manually." | tee -a "$REPORT"
    return 1
  fi
  
  echo "SSH configuration test: PASSED" | tee -a "$REPORT"
  
  # Add rollback command for service restart
  echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
  
  if ! systemctl restart "$SSH_SERVICE"; then
    echo "ERROR: Failed to restart SSH service!" | tee -a "$REPORT"
    return 1
  fi
  
  echo "SSH service restart initiated..." | tee -a "$REPORT"
  
  # Wait for service to fully start
  local attempts=0
  local max_attempts=10
  while [[ $attempts -lt $max_attempts ]]; do
    if systemctl is-active "$SSH_SERVICE" >/dev/null 2>&1; then
      echo "SSH service is running on port $(get_current_ssh_port)" | tee -a "$REPORT"
      
      echo
      echo "IMPORTANT: Test your SSH connection now!"
      echo "New connection command:"
      if [[ -n "$(get_current_allow_users)" ]]; then
        local first_user=$(get_current_allow_users | awk '{print $1}' | cut -d'@' -f1)
        echo "ssh -p $(get_current_ssh_port) $first_user@$(hostname -I | awk '{print $1}')"
      else
        echo "ssh -p $(get_current_ssh_port) yourusername@$(hostname -I | awk '{print $1}')"
      fi
      echo
      return 0
    fi
    ((attempts++))
    sleep 1
  done
  
  echo "WARNING: SSH service status unclear after restart!" | tee -a "$REPORT"
  echo "Please verify manually: systemctl status $SSH_SERVICE" | tee -a "$REPORT"
  return 1
}

# ---------- Finalize Report ----------
finalize_report() {
  {
    echo
    echo "Session Summary:"
    echo "================"
    echo "End time: $(date)"
    echo "Final SSH port: $(get_current_ssh_port)"
    echo "Final AllowUsers: $(get_current_allow_users || echo "(not set)")"
    echo
    echo "Files changed during this session:"
    while IFS= read -r file; do
      echo "  - $file"
    done < "$CHANGED_INDEX"
    echo
    echo "All backups stored in: $BACKUP_DIR"
    echo "Rollback script: $ROLLBACK"
    echo
    echo "To rollback all changes from this session:"
    echo "  sudo $ROLLBACK"
  } >> "$REPORT"
  
  # Finish rollback script
  {
    echo
    echo "systemctl restart ${SSH_SERVICE}"
    echo "echo 'SSH configuration rollback completed.'"
  } >> "$ROLLBACK"
  
  echo
  echo "=================================="
  echo "SSH Configuration Session Complete"
  echo "=================================="
  echo "Report: $REPORT"
  echo "Rollback: $ROLLBACK"
  echo
}

# ---------- Run Main ----------
main
