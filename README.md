# Proxmox SSH Hardening Suite

**Automated SSH security hardening and configuration management for Proxmox LXC containers and VMs running Debian/Ubuntu.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)

## 🚀 Quick Start

### One-Line SSH Hardening
```bash
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-hardening.sh | sudo bash
```

### Multi-IP Network Access Setup
```bash
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-multi-ip-config.sh | sudo bash
```

## 📋 Scripts Overview

| Script | Purpose | Use Case |
|--------|---------|----------|
| `ssh-hardening.sh` | Initial SSH security hardening | Fresh LXC/VM setup |
| `ssh-config-manager.sh` | Comprehensive SSH config management | Ongoing maintenance |
| `ssh-multi-ip-config.sh` | Quick multi-network access setup | Home/office/VPN access |
| `ssh-validation.sh` | Validate hardening configuration | Post-setup verification |

## 🔐 Security Features

### 🛡️ **SSH Hardening (`ssh-hardening.sh`)**
- ✅ **Disable root login** and password authentication
- ✅ **Change SSH port** (default: 2222, customizable)
- ✅ **Strong encryption algorithms** (Ed25519, modern ciphers)
- ✅ **Connection limits** (MaxAuthTries, MaxSessions, timeouts)
- ✅ **User access restrictions** via AllowUsers directive

### 🔑 **Key Management**
- ✅ **Encrypted Ed25519 keys** (recommended, quantum-resistant)
- ✅ **RSA-4096 keys** (legacy compatibility)
- ✅ **Strong random passphrases** (32-character entropy)
- ✅ **Automatic key installation** to authorized_keys
- ✅ **Proper file permissions** (600 for private keys)

### 🌐 **Multi-Network Support**
- ✅ **CIDR notation** for subnets (`192.168.1.0/24`)
- ✅ **Specific IP addresses** (`10.0.0.100`)
- ✅ **Hostname support** for dynamic IPs
- ✅ **Multiple location access** (office, home, VPN)

### 🔄 **Safety & Recovery**
- ✅ **Automatic backups** of all modified files
- ✅ **Rollback scripts** generated for emergency recovery
- ✅ **Configuration validation** before applying changes
- ✅ **Service testing** before restart

## 📖 Usage Guide

### Initial Setup (New LXC/VM)

```bash
# Download and run the hardening script
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-hardening.sh
chmod +x ssh-hardening.sh
sudo ./ssh-hardening.sh
```

**During setup, you'll configure:**
- Admin username (default: `admin`)
- SSH port (default: `2222`) 
- Network restrictions (optional)
- Key generation (Ed25519 + RSA-4096)

### Multi-Location Access Setup

Perfect for users who need SSH access from:
- 🏢 **Office** (via Teleport/UniFi)
- 🏠 **Home Network 1** (`192.168.1.0/24`)
- 🏠 **Home Network 2** (`192.168.50.0/24`)

```bash
# Quick multi-IP configuration
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-multi-ip-config.sh
chmod +x ssh-multi-ip-config.sh
sudo ./ssh-multi-ip-config.sh
```

**Example configuration:**
```
AllowUsers admin@10.0.0.0/8 admin@192.168.1.0/24 admin@192.168.50.0/24
```

### Ongoing Configuration Management

```bash
# Full-featured configuration manager
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-config-manager.sh
chmod +x ssh-config-manager.sh
sudo ./ssh-config-manager.sh
```

**Features include:**
- 🔧 Change SSH port
- 👥 Modify user access (AllowUsers)
- 🔑 Add/remove SSH keys
- ⚙️ Adjust security settings
- 📊 View current configuration

### Validation & Testing

```bash
# Validate your SSH hardening
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-validation.sh
chmod +x ssh-validation.sh
sudo ./ssh-validation.sh
```

## 📁 Output Files

All scripts create timestamped files in `/root/`:

### Initial Hardening Output
```
/root/ssh-hardening-report-TIMESTAMP.txt     # Complete setup report
/root/ssh-generated-keys-TIMESTAMP/          # Private & public keys
/root/ssh-hardening-backups-TIMESTAMP/       # Original file backups
/root/ssh-hardening-rollback-TIMESTAMP.sh    # Emergency recovery script
```

### Configuration Changes Output
```
/root/ssh-config-changes-TIMESTAMP.txt       # Change summary
/root/ssh-config-backups-TIMESTAMP/          # File backups
/root/ssh-config-rollback-TIMESTAMP.sh       # Rollback script
```

## ⚡ Example Workflows

### Scenario 1: New Proxmox LXC Container
```bash
# 1. Initial hardening
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-hardening.sh | sudo bash

# 2. Test connection (in new terminal)
ssh -i /root/ssh-generated-keys-*/admin_ed25519 -p 2222 admin@your-server-ip

# 3. Download private keys to your local machine
scp -P 2222 admin@your-server-ip:/root/ssh-generated-keys-*/admin_ed25519 ~/.ssh/
```

### Scenario 2: Multi-Location Access (MacBook User)
```bash
# Configure access from office and multiple home networks
sudo ./ssh-multi-ip-config.sh

# Enter networks when prompted:
# - 10.0.0.0/8        (office/Teleport)
# - 192.168.1.0/24    (home subnet 1)
# - 192.168.50.0/24   (home subnet 2)
```

### Scenario 3: Adding New SSH Key
```bash
# Use the configuration manager
sudo ./ssh-config-manager.sh
# Select: 3) Add/remove authorized SSH keys
# Select: 1) Add new SSH key to user
```

## 🚨 Emergency Recovery

### If Locked Out via SSH
1. **Use Proxmox Console** to access the container/VM directly
2. **Run the rollback script:**
   ```bash
   sudo /root/ssh-*-rollback-TIMESTAMP.sh
   ```
3. **Or restore manually:**
   ```bash
   sudo cp /root/ssh-*-backups-TIMESTAMP/sshd_config.*.bak /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```

### Connection After Hardening
```bash
# Standard connection
ssh -i ~/.ssh/your_private_key -p 2222 admin@your-server-ip

# With specific key and verbose output
ssh -i ~/.ssh/admin_ed25519 -p 2222 -v admin@your-server-ip
```

## 🔧 Requirements

- **Operating System:** Debian 10+, Ubuntu 18.04+, Proxmox LXC/VM
- **Access Level:** Root privileges required
- **Dependencies:** OpenSSH server, systemctl
- **Network:** Outbound internet access for downloads

## ⚠️ Security Considerations

### Before Running
- ✅ **Test on non-production systems first**
- ✅ **Ensure Proxmox console access is available**
- ✅ **Have alternative access methods ready**
- ✅ **Review network ranges and firewall rules**

### After Running
- ✅ **Test SSH connection immediately** (don't close current session)
- ✅ **Save private keys securely** on your local machine
- ✅ **Update SSH client configuration** with new port
- ✅ **Configure firewall rules** for new SSH port if needed

### Best Practices
- 🔐 **Use strong passphrases** for private keys (auto-generated)
- 🔒 **Store private keys securely** (use SSH agent, encrypted storage)
- 🌐 **Restrict network access** using AllowUsers with specific IPs/subnets
- 📝 **Keep configuration reports** for documentation
- 🔄 **Regular backups** of SSH configurations

## 🐛 Troubleshooting

### Common Issues

**Issue: SSH connection refused after hardening**
```bash
# Check if SSH is running on new port
sudo netstat -tlnp | grep :2222
# or
sudo ss -tlnp | grep :2222

# Check SSH service status
sudo systemctl status ssh
```

**Issue: Permission denied (publickey)**
```bash
# Verify key permissions
chmod 600 ~/.ssh/your_private_key

# Test with verbose output
ssh -i ~/.ssh/your_private_key -p 2222 -v admin@your-server-ip
```

**Issue: Connection timeout**
```bash
# Check firewall rules
sudo ufw status
# Add rule for new SSH port
sudo ufw allow 2222/tcp
```

### Getting Help

1. **Check the generated report files** for configuration details
2. **Use the validation script** to verify setup
3. **Review SSH logs:** `sudo journalctl -u ssh -f`
4. **Test configuration:** `sudo sshd -t`

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⭐ Acknowledgments

- Built for Proxmox homelab environments
- Optimized for multi-location access scenarios
- Designed with safety and recoverability in mind

---

**⚠️ Important:** Always test SSH access before closing your current session. Keep Proxmox console access available as a backup method.
