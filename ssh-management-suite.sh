#!/usr/bin/env bash
# SSH Management Suite
# Unified SSH hardening, configuration, and rollback management
# v3.1 - Fixed function ordering

set -Eeuo pipefail

# ---------- Global Variables ----------
VERSION="3.1"
NOW=""
REPORT=""
BACKUP_DIR=""
ROLLBACK=""
BACKUP_INDEX=""
CHANGED_INDEX=""
SSH_SERVICE=""

# ---------- Core Helper Functions (Must be defined first) ----------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root (sudo -i or sudo $0)"; exit 1
  fi
}

timestamp() { 
  date +%F-%H%M%S; 
}

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

# ---------- File Management Functions ----------
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
      
      # Add to rollback script
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

append_line_with_backup() {
  local target="$1"
  local line="$2"
  mkdir -p "$(dirname "$target")"
  if [[ ! -e "$target" ]]; then
    printf "%s\n" "$line" > "$target"
    echo "Created $target" | tee -a "$REPORT"
    echo "$target" >> "$CHANGED_INDEX"
    return
  fi
  backup_file "$target"
  if ! grep -Fqx -- "$line" "$target"; then
    printf "%s\n" "$line" >> "$target"
    echo "Appended to $target: $line" | tee -a "$REPORT"
  else
    echo "Already present in $target: $line" | tee -a "$REPORT"
  fi
  echo "$target" >> "$CHANGED_INDEX"
}

# ---------- SSH Hardening Implementation Functions ----------
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
    
    # Set random password for the admin user
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
    
    echo "HAS_ED25519=true" >> "$BACKUP_DIR/_key_flags.txt"
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
    
    echo "HAS_RSA=true" >> "$BACKUP_DIR/_key_flags.txt"
  fi
}

install_ssh_keys() {
  local admin_user="$1"
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  
  if [[ ! -f "$BACKUP_DIR/_key_flags.txt" ]]; then
    return 0
  fi
  
  if ASK "Install generated public keys into ~$admin_user/.ssh/authorized_keys?"; then
    # Create .ssh directory and authorized_keys for admin user
    su - "$admin_user" -s /bin/bash -c 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys'
    
    # Backup existing authorized_keys if it exists and has content
    local admin_auth_keys="/home/$admin_user/.ssh/authorized_keys"
    if [[ -s "$admin_auth_keys" ]]; then
      backup_file "$admin_auth_keys"
    fi
    
    # Install keys
    if grep -q "HAS_ED25519=true" "$BACKUP_DIR/_key_flags.txt"; then
      cat "${keys_dir}/${admin_user}_ed25519.pub" >> "$admin_auth_keys"
      echo "Installed Ed25519 public key to $admin_auth_keys" | tee -a "$REPORT"
    fi
    
    if grep -q "HAS_RSA=true" "$BACKUP_DIR/_key_flags.txt"; then
      cat "${keys_dir}/${admin_user}_rsa4096.pub" >> "$admin_auth_keys"
      echo "Installed RSA-4096 public key to $admin_auth_keys" | tee -a "$REPORT"
    fi
    
    # Set proper permissions
    chown "$admin_user:$admin_user" "$admin_auth_keys"
    chmod 600 "$admin_auth_keys"
    chmod 700 "/home/$admin_user/.ssh"
    
    echo "$admin_auth_keys" >> "$CHANGED_INDEX"
    echo "chown root:root '$admin_auth_keys'; rm -f '$admin_auth_keys'" >> "$ROLLBACK"
  fi
}

apply_ssh_hardening() {
  local admin_user="$1"
  local ssh_port="$2"
  local allow_from="$3"
  
  if ASK "Apply SSH hardening configuration?"; then
    
    # Build AllowUsers directive
    local allow_users=""
    if [[ -n "$allow_from" ]]; then
      allow_users="AllowUsers ${admin_user}@${allow_from}"
    else
      allow_users="AllowUsers ${admin_user}"
    fi
    
    # Create hardened SSH config
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

restart_ssh_service() {
  local ssh_port="$1"
  
  if ASK "Restart SSH service to apply changes?"; then
    echo "Testing SSH configuration..." | tee -a "$REPORT"
    
    if ! sshd -t; then
      echo "ERROR: SSH configuration test failed!" | tee -a "$REPORT"
      echo "Not restarting SSH service. Please check configuration manually." | tee -a "$REPORT"
      return 1
    fi
    
    echo "SSH configuration test: PASSED" | tee -a "$REPORT"
    
    # Handle socket activation that can interfere with port changes
    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
      echo "Disabling SSH socket activation to allow custom port..." | tee -a "$REPORT"
      systemctl stop ssh.socket >/dev/null 2>&1
      systemctl disable ssh.socket >/dev/null 2>&1
      systemctl mask ssh.socket >/dev/null 2>&1
      echo "systemctl unmask ssh.socket; systemctl enable ssh.socket" >> "$ROLLBACK"
    fi
    
    # Add rollback command for service restart
    echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
    
    # Proper service restart sequence
    systemctl stop "$SSH_SERVICE" >/dev/null 2>&1 || true
    sleep 1
    pkill -f sshd >/dev/null 2>&1 || true
    systemctl start "$SSH_SERVICE"
    echo "SSH service restarted" | tee -a "$REPORT"
    
    # Wait and verify service is running on correct port
    local attempts=0
    local max_attempts=10
    while [[ $attempts -lt $max_attempts ]]; do
      if netstat -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd; then
        echo "SSH service is running on port $ssh_port" | tee -a "$REPORT"
        break
      elif ss -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd; then
        echo "SSH service is running on port $ssh_port" | tee -a "$REPORT"
        break
      fi
      ((attempts++))
      sleep 1
    done
    
    if [[ $attempts -eq $max_attempts ]]; then
      echo "WARNING: Could not verify SSH is listening on port $ssh_port" | tee -a "$REPORT"
      echo "Check manually with: netstat -tlnp | grep :$ssh_port" | tee -a "$REPORT"
      
      # Try to fix common port issues
      echo "Attempting to fix port configuration..." | tee -a "$REPORT"
      
      # Remove any conflicting Port lines and set correct one
      sed -i '/^Port/d' /etc/ssh/sshd_config
      sed -i "1i Port $ssh_port" /etc/ssh/sshd_config
      
      # Remove deprecated options that cause warnings
      sed -i '/UsePrivilegeSeparation/d' /etc/ssh/sshd_config
      
      # Test and restart again
      if sshd -t; then
        systemctl restart "$SSH_SERVICE"
        sleep 2
        if netstat -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd || ss -tlnp 2>/dev/null | grep ":${ssh_port} " | grep -q sshd; then
          echo "Port configuration fixed - SSH now running on port $ssh_port" | tee -a "$REPORT"
        else
          echo "ERROR: SSH still not listening on correct port. Manual intervention required." | tee -a "$REPORT"
        fi
      else
        echo "ERROR: SSH configuration has syntax errors!" | tee -a "$REPORT"
      fi
    fi
  fi
}

finalize_hardening_report() {
  local admin_user="$1"
  local ssh_port="$2"
  local keys_dir="/root/ssh-generated-keys-${NOW}"
  
  {
    echo
    echo "Post-Hardening Connection Instructions:"
    echo "======================================"
    echo "1. Test SSH connection BEFORE closing this session:"
    if [[ -f "${keys_dir}/${admin_user}_ed25519" ]]; then
      echo "   ssh -i ${keys_dir}/${admin_user}_ed25519 -p ${ssh_port} ${admin_user}@$(hostname -I | awk '{print $1}')"
    else
      echo "   ssh -p ${ssh_port} ${admin_user}@$(hostname -I | awk '{print $1}')"
    fi
    echo
    echo "2. If connection fails, rollback with:"
    echo "   $ROLLBACK"
    echo
    echo "3. Download private keys from:"
    echo "   $keys_dir"
    echo
    echo "4. Files changed during hardening:"
    while IFS= read -r file; do
      echo "   - $file"
    done < "$CHANGED_INDEX"
    echo
    echo "5. All backups stored in:"
    echo "   $BACKUP_DIR"
    echo
    echo "IMPORTANT: Test SSH access before logging out!"
    echo "If locked out, use Proxmox console to rollback."
  } >> "$REPORT"
  
  # Finish rollback script
  {
    echo
    echo "systemctl restart ${SSH_SERVICE}"
    echo "echo 'SSH hardening rollback completed.'"
  } >> "$ROLLBACK"
  
  # Set proper permissions on generated files
  chmod 600 "$keys_dir"/* 2>/dev/null || true
  chmod 644 "$keys_dir"/*.pub 2>/dev/null || true
  local pubkeys_file="${keys_dir}/ALL_PUBLIC_KEYS.txt"
  [[ -f "$pubkeys_file" ]] && chmod 644 "$pubkeys_file"
  chmod 644 "$REPORT"
  
  # Copy key info to report for easy access
  if [[ -f "$pubkeys_file" ]]; then
    cat "$pubkeys_file" >> "$REPORT"
  fi
  
  echo
  echo "=================================="
  echo "SSH Hardening Complete!"
  echo "=================================="
  echo "Report: $REPORT"
  echo "Keys: $keys_dir"
  echo "Rollback: $ROLLBACK"
  echo
  echo "CRITICAL: Test SSH connection now!"
  if [[ -f "${keys_dir}/${admin_user}_ed25519" ]]; then
    echo "Test command:"
    echo "ssh -i ${keys_dir}/${admin_user}_ed25519 -p ${ssh_port} ${admin_user}@$(hostname -I | awk '{print $1}')"
  fi
  echo
}

# ---------- Main Feature Functions ----------
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
    echo "Backups dir: ${BACKUP_DIR}"
    echo "SSH service: ${SSH_SERVICE}"
    echo "Current SSH port: $(get_current_ssh_port)"
    echo "=================================="
    echo
  } > "$REPORT"
  
  # Initialize rollback script
  {
    echo "#!/usr/bin/env bash"
    echo "# SSH Hardening Rollback Script - ${NOW}"
    echo "set -Eeuo pipefail"
    echo
    echo "echo 'Rolling back SSH hardening changes...'"
    echo
  } > "$ROLLBACK"
  chmod +x "$ROLLBACK"
  
  # User inputs
  read -r -p "Admin username to create/use for SSH (default: admin): " ADMIN </dev/tty || ADMIN="admin"
  ADMIN="${ADMIN:-admin}"
  
  read -r -p "SSH port to use (default: 2222): " SSH_PORT </dev/tty || SSH_PORT="2222"
  SSH_PORT="${SSH_PORT:-2222}"
  
  read -r -p "Optional allow-from (CIDR/IP/hostname) for ${ADMIN} (empty = any): " ALLOW_FROM </dev/tty || ALLOW_FROM=""
  
  # Execute hardening steps
  create_admin_user "$ADMIN"
  generate_ssh_keys "$ADMIN"
  install_ssh_keys "$ADMIN"
  apply_ssh_hardening "$ADMIN" "$SSH_PORT" "$ALLOW_FROM"
  restart_ssh_service "$SSH_PORT"
  finalize_hardening_report "$ADMIN" "$SSH_PORT"
}

multi_ip_config() {
  NOW="$(timestamp)"
  REPORT="/root/ssh-multi-ip-config-${NOW}.txt"
  SSH_SERVICE="$(detect_ssh_service)"
  
  echo "SSH Multi-IP Configuration"
  echo "=========================="
  echo
  
  # Get current configuration
  local current_port=$(get_current_ssh_port)
  local current_allow=$(get_current_allow_users)
  
  echo "Current SSH port: $current_port"
  echo "Current AllowUsers: ${current_allow:-"(not set)"}"
  echo
  
  # Get username
  while true; do
    read -r -p "Enter your SSH username: " username </dev/tty
    if [[ -n "$username" ]] && [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      if id "$username" &>/dev/null; then
        break
      else
        echo "WARNING: User '$username' does not exist on this system."
        if ASK "Continue anyway?"; then
          break
        fi
      fi
    else
      echo "ERROR: Invalid username. Use only letters, numbers, underscores, and hyphens."
    fi
  done
  
  # Get networks
  echo
  echo "Configure access from multiple locations:"
  echo "========================================="
  echo "Enter your network information (press Enter after each, empty line to finish):"
  echo
  echo "Examples:"
  echo "  Office (Teleport/UniFi): 10.0.0.0/8"
  echo "  Home subnet 1: 192.168.1.0/24"
  echo "  Home subnet 2: 192.168.50.0/24"
  echo "  Specific IP: 203.0.113.45"
  echo
  
  local networks=()
  while true; do
    read -r -p "Enter network/IP (empty to finish): " network </dev/tty
    if [[ -z "$network" ]]; then
      break
    fi
    if validate_network "$network"; then
      networks+=("$network")
      echo "✓ Added: $network"
    else
      echo "✗ Invalid format: $network (skipped)"
      echo "  Valid formats: 192.168.1.0/24, 10.0.0.100, hostname.com"
    fi
  done
  
  if [[ ${#networks[@]} -eq 0 ]]; then
    echo "ERROR: No valid networks specified."
    return 1
  fi
  
  # Build AllowUsers line
  local allow_users_line="AllowUsers"
  for net in "${networks[@]}"; do
    allow_users_line="$allow_users_line ${username}@${net}"
  done
  
  echo
  echo "Proposed configuration:"
  echo "======================"
  echo "SSH Port: $current_port"
  echo "Username: $username"
  echo "Allowed from:"
  for net in "${networks[@]}"; do
    echo "  - $net"
  done
  echo
  echo "Full AllowUsers line:"
  echo "$allow_users_line"
  echo
  
  if ! ASK "Apply this configuration?"; then
    echo "Configuration cancelled."
    return 1
  fi
  
  # Apply configuration
  local backup_file="/root/sshd_config.backup.${NOW}"
  if ! cp /etc/ssh/sshd_config "$backup_file"; then
    echo "ERROR: Failed to create backup. Aborting."
    return 1
  fi
  echo "✓ Backup created: $backup_file"
  
  echo "Applying configuration..."
  
  local temp_config="/tmp/sshd_config.tmp.$$"
  
  # Create new config without existing AllowUsers lines
  if ! grep -v "^AllowUsers" /etc/ssh/sshd_config > "$temp_config"; then
    echo "ERROR: Failed to process SSH config. Aborting."
    rm -f "$temp_config"
    return 1
  fi
  
  # Add new AllowUsers line
  echo "$allow_users_line" >> "$temp_config"
  
  # Test the new configuration
  echo "Testing new SSH configuration..."
  if ! sshd -t -f "$temp_config"; then
    echo "ERROR: New SSH configuration is invalid!"
    echo "Aborting - no changes made."
    rm -f "$temp_config"
    return 1
  fi
  
  echo "✓ Configuration test passed"
  
  # Apply the new configuration
  if ! cp "$temp_config" /etc/ssh/sshd_config; then
    echo "ERROR: Failed to apply new configuration!"
    echo "Restoring backup..."
    cp "$backup_file" /etc/ssh/sshd_config
    rm -f "$temp_config"
    return 1
  fi
  
  rm -f "$temp_config"
  echo "✓ Configuration applied"
  
  # Restart SSH service
  echo "Restarting SSH service..."
  if ! systemctl restart "$SSH_SERVICE"; then
    echo "ERROR: Failed to restart SSH service!"
    echo "Restoring backup configuration..."
    cp "$backup_file" /etc/ssh/sshd_config
    systemctl restart "$SSH_SERVICE"
    echo "Backup configuration restored."
    return 1
  fi
  
  # Wait for service to start and verify
  sleep 2
  if ! systemctl is-active "$SSH_SERVICE" >/dev/null; then
    echo "WARNING: SSH service may not be running properly!"
    echo "Please check: systemctl status $SSH_SERVICE"
  fi
  
  echo "✓ SSH service restarted"
  
  # Create report
  {
    echo "SSH Multi-IP Configuration Report - $NOW"
    echo "========================================"
    echo "Host: $(hostname)"
    echo "Applied: $(date)"
    echo
    echo "Configuration:"
    echo "SSH Port: $current_port"
    echo "Username: $username"
    echo "Allowed Networks:"
    for net in "${networks[@]}"; do
      echo "  - $net"
    done
    echo
    echo "Full AllowUsers line:"
    echo "$allow_users_line"
    echo
    echo "Connection examples:"
    echo "==================="
    local host_ip=$(hostname -I | awk '{print $1}')
    echo "From any configured network:"
    echo "  ssh -p $current_port $username@$host_ip"
    echo
    echo "Backup Information:"
    echo "==================="
    echo "Original config backup: $backup_file"
    echo
    echo "To rollback this change:"
    echo "  sudo cp $backup_file /etc/ssh/sshd_config"
    echo "  sudo systemctl restart $SSH_SERVICE"
