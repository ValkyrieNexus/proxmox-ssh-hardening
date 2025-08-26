#!/usr/bin/env bash
# ==========================================
# DEPRECATED: This script is deprecated
# ==========================================
# Please use the new SSH Management Suite instead:
#   curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash
#
# This script has known issues with:
# - Socket activation conflicts
# - Port binding problems on modern systemd
# - Limited rollback capabilities
#
# The SSH Management Suite provides all functionality
# of this script plus comprehensive fixes and features.
# ==========================================

echo "WARNING: This script is deprecated!"
echo "Please use the SSH Management Suite instead:"
echo "curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash"
echo
read -p "Continue with deprecated script anyway? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting. Please use the SSH Management Suite."
    exit 1
fi

# Original script content follows...
#!/usr/bin/env bash
# Secure SSH setup & key generator
# Works on Debian/Ubuntu/Proxmox (VM/LXC)
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
    read -r -p "$prompt [y/n]: " ans
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
  # $1 target path, $2 content
  local target="$1"
  local content="$2"
  mkdir -p "$(dirname "$target")"
  if [[ -e "$target" ]]; then
    backup_file "$target"
  fi
  printf "%s" "$content" > "$target"
  echo "Wrote $target" | tee -a "$REPORT"
  echo "$target" >> "$CHANGED_INDEX"
  
  # Add to rollback script
  if [[ -e "${BACKUP_DIR}/$(basename "$target").${NOW}.bak" ]]; then
    echo "cp '${BACKUP_DIR}/$(basename "$target").${NOW}.bak' '$target'" >> "$ROLLBACK"
  else
    echo "rm -f '$target'" >> "$ROLLBACK"
  fi
}

random_pass() { 
  openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
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

# ---------- Init ----------
require_root
NOW="$(timestamp)"
REPORT="/root/ssh-hardening-report-${NOW}.txt"
BACKUP_DIR="/root/ssh-hardening-backups-${NOW}"
ROLLBACK="/root/ssh-hardening-rollback-${NOW}.sh"
BACKUP_INDEX="${BACKUP_DIR}/_backup-index.txt"
CHANGED_INDEX="${BACKUP_DIR}/_changed-files.txt"
mkdir -p "$BACKUP_DIR"
touch "$BACKUP_INDEX" "$CHANGED_INDEX"
SSH_SERVICE="$(detect_ssh_service)"
CURRENT_SSH_PORT="$(get_current_ssh_port)"

{
  echo "SSH Hardening & Key Report - ${NOW}"
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "IP: $(hostname -I | awk '{print $1}')"
  echo "Backups dir: ${BACKUP_DIR}"
  echo "SSH service: ${SSH_SERVICE}"
  echo "Current SSH port: ${CURRENT_SSH_PORT}"
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

# ---------- User inputs ----------
echo "SSH Hardening Script v2.0"
echo "========================="
echo

read -r -p "Admin username to create/use for SSH (default: admin): " ADMIN
ADMIN="${ADMIN:-admin}"

read -r -p "SSH port to use (default: 2222): " SSH_PORT
SSH_PORT="${SSH_PORT:-2222}"

read -r -p "Optional allow-from (CIDR/IP/hostname) for ${ADMIN} (empty = any): " ALLOW_FROM

# ---------- Step 1: Ensure admin user with sudo ----------
echo
if ASK "Create or ensure admin user '${ADMIN}' with sudo?"; then
  if id "$ADMIN" &>/dev/null; then
    echo "User '$ADMIN' exists." | tee -a "$REPORT"
  else
    adduser --disabled-password --gecos "SSH Admin User" "$ADMIN"
    echo "Created user '$ADMIN'." | tee -a "$REPORT"
    echo "userdel -r '$ADMIN'" >> "$ROLLBACK"
  fi
  
  usermod -aG sudo "$ADMIN"
  echo "Granted sudo to '$ADMIN'." | tee -a "$REPORT"
  
  # Set random password for the admin user
  ADMIN_PASS="$(random_pass)"
  echo "$ADMIN:$ADMIN_PASS" | chpasswd
  {
    echo "Admin User Credentials:"
    echo "Username: $ADMIN"
    echo "Password: $ADMIN_PASS"
    echo "(Password login will be disabled after SSH key setup)"
    echo
  } >> "$REPORT"
fi

# ---------- Step 2: Generate encrypted keys ----------
KEYS_DIR="/root/ssh-generated-keys-${NOW}"
mkdir -p "$KEYS_DIR"
PUBKEYS_OUT="${KEYS_DIR}/ALL_PUBLIC_KEYS.txt"
touch "$PUBKEYS_OUT"

{
  echo "SSH Key Information:"
  echo "==================="
} >> "$PUBKEYS_OUT"

if ASK "Generate encrypted Ed25519 key for '${ADMIN}'?"; then
  PASS_ED="$(random_pass)"
  ssh-keygen -t ed25519 -a 100 -N "${PASS_ED}" -C "${ADMIN}@$(hostname)-ed25519-${NOW}" -f "${KEYS_DIR}/${ADMIN}_ed25519" >/dev/null 2>&1
  echo "Generated Ed25519 keypair: ${KEYS_DIR}/${ADMIN}_ed25519{,.pub}" | tee -a "$REPORT"
  
  {
    echo
    echo "### ${ADMIN} Ed25519 Key"
    echo "Private key: ${KEYS_DIR}/${ADMIN}_ed25519"
    echo "Public key : ${KEYS_DIR}/${ADMIN}_ed25519.pub"
    echo "Passphrase : ${PASS_ED}"
    echo "Public key content:"
    cat "${KEYS_DIR}/${ADMIN}_ed25519.pub"
    echo
  } >> "$PUBKEYS_OUT"
  
  HAS_ED25519=true
fi

if ASK "Also generate RSA-4096 key for compatibility?"; then
  PASS_RSA="$(random_pass)"
  ssh-keygen -t rsa -b 4096 -o -a 100 -N "${PASS_RSA}" -C "${ADMIN}@$(hostname)-rsa4096-${NOW}" -f "${KEYS_DIR}/${ADMIN}_rsa4096" >/dev/null 2>&1
  echo "Generated RSA-4096 keypair: ${KEYS_DIR}/${ADMIN}_rsa4096{,.pub}" | tee -a "$REPORT"
  
  {
    echo "### ${ADMIN} RSA-4096 Key"
    echo "Private key: ${KEYS_DIR}/${ADMIN}_rsa4096"
    echo "Public key : ${KEYS_DIR}/${ADMIN}_rsa4096.pub" 
    echo "Passphrase : ${PASS_RSA}"
    echo "Public key content:"
    cat "${KEYS_DIR}/${ADMIN}_rsa4096.pub"
    echo
  } >> "$PUBKEYS_OUT"
  
  HAS_RSA=true
fi

# ---------- Step 3: Install public keys ----------
if [[ -n "${HAS_ED25519:-}${HAS_RSA:-}" ]] && ASK "Install generated public keys into ~$ADMIN/.ssh/authorized_keys?"; then
  
  # Create .ssh directory and authorized_keys for admin user
  su - "$ADMIN" -s /bin/bash -c 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys'
  
  # Backup existing authorized_keys if it exists and has content
  ADMIN_AUTH_KEYS="/home/$ADMIN/.ssh/authorized_keys"
  if [[ -s "$ADMIN_AUTH_KEYS" ]]; then
    backup_file "$ADMIN_AUTH_KEYS"
  fi
  
  # Install keys
  if [[ -n "${HAS_ED25519:-}" ]]; then
    cat "${KEYS_DIR}/${ADMIN}_ed25519.pub" >> "$ADMIN_AUTH_KEYS"
    echo "Installed Ed25519 public key to $ADMIN_AUTH_KEYS" | tee -a "$REPORT"
  fi
  
  if [[ -n "${HAS_RSA:-}" ]]; then
    cat "${KEYS_DIR}/${ADMIN}_rsa4096.pub" >> "$ADMIN_AUTH_KEYS"
    echo "Installed RSA-4096 public key to $ADMIN_AUTH_KEYS" | tee -a "$REPORT"
  fi
  
  # Set proper permissions
  chown "$ADMIN:$ADMIN" "$ADMIN_AUTH_KEYS"
  chmod 600 "$ADMIN_AUTH_KEYS"
  chmod 700 "/home/$ADMIN/.ssh"
  
  echo "$ADMIN_AUTH_KEYS" >> "$CHANGED_INDEX"
  echo "chown root:root '$ADMIN_AUTH_KEYS'; rm -f '$ADMIN_AUTH_KEYS'" >> "$ROLLBACK"
fi

# ---------- Step 4: Harden SSH Configuration ----------
if ASK "Apply SSH hardening configuration?"; then
  
  # Build AllowUsers directive
  if [[ -n "$ALLOW_FROM" ]]; then
    ALLOW_USERS="AllowUsers ${ADMIN}@${ALLOW_FROM}"
  else
    ALLOW_USERS="AllowUsers ${ADMIN}"
  fi
  
  # Create hardened SSH config
  SSH_CONFIG="# SSH Hardening Configuration - Applied ${NOW}
# Original config backed up to ${BACKUP_DIR}

# Connection settings
Port ${SSH_PORT}
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
${ALLOW_USERS}
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
UsePrivilegeSeparation sandbox

# Logging
SyslogFacility AUTHPRIV
LogLevel INFO

# Banner
Banner none
PrintMotd yes
"

  install_file_with_backup "/etc/ssh/sshd_config" "$SSH_CONFIG"
  
  {
    echo "SSH Configuration Changes:"
    echo "========================="
    echo "Port changed to: $SSH_PORT"
    echo "Root login: DISABLED"
    echo "Password authentication: DISABLED"
    echo "Public key authentication: ENABLED"
    echo "User restrictions: $ALLOW_USERS"
    echo "Max auth tries: 3"
    echo "Connection timeout: 5 minutes"
    echo
  } >> "$REPORT"
fi

# ---------- Step 5: Restart SSH and validate ----------
if ASK "Restart SSH service to apply changes?"; then
  echo "Testing SSH configuration..." | tee -a "$REPORT"
  
  if sshd -t; then
    echo "SSH configuration test: PASSED" | tee -a "$REPORT"
    
    # Add rollback command for service restart
    echo "systemctl restart ${SSH_SERVICE}" >> "$ROLLBACK"
    
    systemctl restart "$SSH_SERVICE"
    echo "SSH service restarted successfully" | tee -a "$REPORT"
    
    # Verify service is running
    if systemctl is-active "$SSH_SERVICE" >/dev/null; then
      echo "SSH service is running on port $SSH_PORT" | tee -a "$REPORT"
    else
      echo "WARNING: SSH service may not be running properly!" | tee -a "$REPORT"
    fi
  else
    echo "ERROR: SSH configuration test failed!" | tee -a "$REPORT"
    echo "Not restarting SSH service. Check configuration manually." | tee -a "$REPORT"
    exit 1
  fi
fi

# ---------- Final report and cleanup ----------
{
  echo
  echo "Post-Hardening Connection Instructions:"
  echo "======================================"
  echo "1. Test SSH connection BEFORE closing this session:"
  echo "   ssh -i ${KEYS_DIR}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')"
  echo
  echo "2. If connection fails, rollback with:"
  echo "   $ROLLBACK"
  echo
  echo "3. Download private keys from:"
  echo "   $KEYS_DIR"
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
chmod 600 "$KEYS_DIR"/*
chmod 644 "$KEYS_DIR"/*.pub
chmod 644 "$PUBKEYS_OUT"
chmod 644 "$REPORT"

# Display final summary
echo
echo "=================================="
echo "SSH Hardening Complete!"
echo "=================================="
echo "Report: $REPORT"
echo "Keys: $KEYS_DIR"
echo "Rollback: $ROLLBACK"
echo
echo "CRITICAL: Test SSH connection now!"
if [[ -n "${HAS_ED25519:-}" ]]; then
  echo "Test command:"
  echo "ssh -i ${KEYS_DIR}/${ADMIN}_ed25519 -p ${SSH_PORT} ${ADMIN}@$(hostname -I | awk '{print $1}')"
fi
echo

# Copy key info to report for easy access
cat "$PUBKEYS_OUT" >> "$REPORT"
