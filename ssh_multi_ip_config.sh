#!/usr/bin/env bash
# SSH Multi-IP Quick Configuration
# Set up SSH access from multiple networks/IPs
# v1.1 - Fixed version

set -Eeuo pipefail

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root (sudo -i or sudo $0)"; exit 1
  fi
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

detect_ssh_service() {
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    echo sshd
  else
    echo ssh
  fi
}

timestamp() { date +%F-%H%M%S; }
NOW="$(timestamp)"
REPORT="/root/ssh-multi-ip-config-${NOW}.txt"
SSH_SERVICE="$(detect_ssh_service)"

require_root

echo "SSH Multi-IP Configuration Script v1.1"
echo "======================================"
echo

# Get current configuration
CURRENT_PORT=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
CURRENT_ALLOW=$(grep -E "^AllowUsers\s+" /etc/ssh/sshd_config 2>/dev/null | sed 's/^AllowUsers\s*//' || echo "")

echo "Current SSH port: $CURRENT_PORT"
echo "Current AllowUsers: ${CURRENT_ALLOW:-"(not set)"}"
echo

# Get username
while true; do
  read -r -p "Enter your SSH username: " USERNAME
  if [[ -n "$USERNAME" ]] && [[ "$USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    if id "$USERNAME" &>/dev/null; then
      break
    else
      echo "WARNING: User '$USERNAME' does not exist on this system."
      read -r -p "Continue anyway? [y/n]: " continue_choice
      if [[ "$continue_choice" =~ ^[Yy]$ ]]; then
        break
      fi
    fi
  else
    echo "ERROR: Invalid username. Use only letters, numbers, underscores, and hyphens."
  fi
done

# Create the multi-IP configuration
echo
echo "Configure access from multiple locations:"
echo "========================================="
echo "Enter your network information (press Enter after each, empty line to finish):"
echo
echo "Examples for your setup:"
echo "  Office (Teleport/UniFi): 10.0.0.0/8 or specific IP"
echo "  Home subnet 1: 192.168.1.0/24"
echo "  Home subnet 2: 192.168.50.0/24"
echo "  Specific IP: 203.0.113.45"
echo

NETWORKS=()
while true; do
  read -r -p "Enter network/IP (empty to finish): " NETWORK
  if [[ -z "$NETWORK" ]]; then
    break
  fi
  if validate_network "$NETWORK"; then
    NETWORKS+=("$NETWORK")
    echo "✓ Added: $NETWORK"
  else
    echo "✗ Invalid format: $NETWORK (skipped)"
    echo "  Valid formats: 192.168.1.0/24, 10.0.0.100, hostname.com"
  fi
done

if [[ ${#NETWORKS[@]} -eq 0 ]]; then
  echo "ERROR: No valid networks specified. Exiting."
  exit 1
fi

# Build AllowUsers line
ALLOW_USERS_LINE="AllowUsers"
for net in "${NETWORKS[@]}"; do
  ALLOW_USERS_LINE="$ALLOW_USERS_LINE ${USERNAME}@${net}"
done

echo
echo "Proposed configuration:"
echo "======================"
echo "SSH Port: $CURRENT_PORT"
echo "Username: $USERNAME"
echo "Allowed from:"
for net in "${NETWORKS[@]}"; do
  echo "  - $net"
done
echo
echo "Full AllowUsers line:"
echo "$ALLOW_USERS_LINE"
echo

read -r -p "Apply this configuration? [y/n]: " CONFIRM
if [[ "$CONFIRM" != [Yy] ]]; then
  echo "Configuration cancelled."
  exit 0
fi

# Backup current config
BACKUP_FILE="/root/sshd_config.backup.${NOW}"
if ! cp /etc/ssh/sshd_config "$BACKUP_FILE"; then
  echo "ERROR: Failed to create backup. Aborting."
  exit 1
fi
echo "✓ Backup created: $BACKUP_FILE"

# Apply configuration
echo "Applying configuration..."

TEMP_CONFIG="/tmp/sshd_config.tmp.$"

# Create new config without existing AllowUsers lines
if ! grep -v "^AllowUsers" /etc/ssh/sshd_config > "$TEMP_CONFIG"; then
  echo "ERROR: Failed to process SSH config. Aborting."
  rm -f "$TEMP_CONFIG"
  exit 1
fi

# Add new AllowUsers line
echo "$ALLOW_USERS_LINE" >> "$TEMP_CONFIG"

# Test the new configuration
echo "Testing new SSH configuration..."
if ! sshd -t -f "$TEMP_CONFIG"; then
  echo "ERROR: New SSH configuration is invalid!"
  echo "Aborting - no changes made."
  rm -f "$TEMP_CONFIG"
  exit 1
fi

echo "✓ Configuration test passed"

# Apply the new configuration
if ! cp "$TEMP_CONFIG" /etc/ssh/sshd_config; then
  echo "ERROR: Failed to apply new configuration!"
  echo "Restoring backup..."
  cp "$BACKUP_FILE" /etc/ssh/sshd_config
  rm -f "$TEMP_CONFIG"
  exit 1
fi

rm -f "$TEMP_CONFIG"
echo "✓ Configuration applied"

# Restart SSH service
echo "Restarting SSH service..."
if ! systemctl restart "$SSH_SERVICE"; then
  echo "ERROR: Failed to restart SSH service!"
  echo "Restoring backup configuration..."
  cp "$BACKUP_FILE" /etc/ssh/sshd_config
  systemctl restart "$SSH_SERVICE"
  echo "Backup configuration restored."
  exit 1
fi

# Wait for service to start and verify
sleep 2
if ! systemctl is-active "$SSH_SERVICE" >/dev/null; then
  echo "WARNING: SSH service may not be running properly!"
  echo "Please check: systemctl status $SSH_SERVICE"
fi

echo "✓ SSH service restarted"

# Create detailed report
{
  echo "SSH Multi-IP Configuration Report - $NOW"
  echo "========================================"
  echo "Host: $(hostname)"
  echo "Applied: $(date)"
  echo
  echo "Configuration:"
  echo "SSH Port: $CURRENT_PORT"
  echo "Username: $USERNAME"
  echo "Allowed Networks:"
  for net in "${NETWORKS[@]}"; do
    echo "  - $net"
  done
  echo
  echo "Full AllowUsers line:"
  echo "$ALLOW_USERS_LINE"
  echo
  echo "Connection examples:"
  echo "==================="
  local host_ip=$(hostname -I | awk '{print $1}')
  echo "From any configured network:"
  echo "  ssh -p $CURRENT_PORT $USERNAME@$host_ip"
  echo
  echo "Testing commands for each network:"
  for net in "${NETWORKS[@]}"; do
    echo "  # From $net"
    echo "  ssh -p $CURRENT_PORT $USERNAME@$host_ip"
  done
  echo
  echo "Backup Information:"
  echo "==================="
  echo "Original config backup: $BACKUP_FILE"
  echo
  echo "To rollback this change:"
  echo "  sudo cp $BACKUP_FILE /etc/ssh/sshd_config"
  echo "  sudo systemctl restart $SSH_SERVICE"
  echo
  echo "Files modified:"
  echo "  /etc/ssh/sshd_config"
  echo
} > "$REPORT"

echo
echo "SUCCESS: SSH multi-IP configuration applied!"
echo "==========================================="
echo "✓ Configuration validated and applied"
echo "✓ SSH service restarted successfully"
echo "✓ Report saved to: $REPORT"
echo
echo "IMPORTANT: Test your connection now from each location:"
echo "ssh -p $CURRENT_PORT $USERNAME@$(hostname -I | awk '{print $1}')"
echo
echo "If you encounter issues, rollback with:"
echo "sudo cp $BACKUP_FILE /etc/ssh/sshd_config && sudo systemctl restart $SSH_SERVICE"
  
  # Create report
  {
    echo "SSH Multi-IP Configuration Report - $NOW"
    echo "========================================"
    echo "Host: $(hostname)"
    echo "Applied: $(date)"
    echo
    echo "Configuration:"
    echo "SSH Port: $CURRENT_PORT"
    echo "Username: $USERNAME"
    echo "Allowed Networks:"
    for net in "${NETWORKS[@]}"; do
      echo "  - $net"
    done
    echo
    echo "Full AllowUsers line:"
    echo "$ALLOW_USERS_LINE"
    echo
    echo "Connection examples:"
    echo "==================="
    local host_ip=$(hostname -I | awk '{print $1}')
    echo "From office/teleport: ssh -p $CURRENT_PORT $USERNAME@$host_ip"
    echo "From home subnet 1:   ssh -p $CURRENT_PORT $USERNAME@$host_ip"
    echo "From home subnet 2:   ssh -p $CURRENT_PORT $USERNAME@$host_ip"
    echo
    echo "Backup of original config:"
    echo "/root/sshd_config.backup.${NOW}"
    echo
    echo "To rollback:"
    echo "sudo cp /root/sshd_config.backup.${NOW} /etc/ssh/sshd_config"
    echo "sudo systemctl restart ssh"
    echo
  } > "$REPORT"
  
  echo "SUCCESS: SSH multi-IP configuration applied!"
  echo "Report saved to: $REPORT"
  echo
  echo "Test your connection now from each location:"
  echo "ssh -p $CURRENT_PORT $USERNAME@$(hostname -I | awk '{print $1}')"
  
else
  echo "ERROR: SSH configuration test failed!"
  echo "Restoring original configuration..."
  cp "/root/sshd_config.backup.${NOW}" /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
  echo "Original configuration restored."
  exit 1
fi