# SSH Management Suite

**Unified SSH hardening, configuration management, and rollback system for Proxmox LXC containers and VMs running Debian/Ubuntu.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)

## 🚀 Quick Start

### One-Line Installation (Recommended)
```bash
# Complete SSH management suite with unified interface
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash
```

### Secure Installation (Download and Review)
```bash
# Download the suite
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh

# Make it executable
chmod +x ssh-management-suite.sh

# Review the script (recommended)
less ssh-management-suite.sh

# Run the suite
sudo ./ssh-management-suite.sh
```

## 📋 SSH Management Suite Features

When you run the suite, you'll see this main menu:

```
SSH Management Suite v3.0
===============================
Host: your-hostname
Current SSH Port: 22

1) Harden SSH (new installation)
2) Configure multi-IP access  
3) Manage/rollback previous sessions
4) Validate current configuration
5) Exit
```

### Option 1: Harden SSH (New Installation)
- **Complete SSH security hardening** for fresh systems
- **Encrypted key generation** (Ed25519 + RSA-4096)
- **Automatic user creation** with sudo privileges
- **Port configuration** (default: 2222)
- **Network access restrictions** (optional)
- **Socket activation handling** (fixes port binding issues)

### Option 2: Configure Multi-IP Access
- **Perfect for multi-location setups** (office + home networks)
- **CIDR subnet support** (`192.168.1.0/24`)
- **Specific IP addresses** (`10.0.0.100`)
- **Hostname support** for dynamic IPs
- **Input validation** and configuration testing

### Option 3: Manage/Rollback Previous Sessions
- **Session discovery** (finds all previous hardening)
- **Interactive rollback** with detailed session info
- **Automated rollback scripts** + manual restoration
- **Safe restoration** with configuration testing

### Option 4: Validate Current Configuration
- **Comprehensive testing** of SSH security settings
- **Port binding verification** 
- **Service status checking**
- **Key file validation**
- **Security audit** with detailed reporting

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

## 📖 Step-by-Step Usage Guide

### Prerequisites
- Debian 10+, Ubuntu 18.04+, or Proxmox LXC/VM
- Root access (sudo privileges)
- Active internet connection
- **Proxmox console access** (critical for recovery)

### Step 1: Launch SSH Management Suite

#### Method A: Direct Execution (Fastest)
```bash
# SSH into your server
ssh root@your-server-ip

# Run the management suite
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash
```

#### Method B: Download and Review (Production Recommended)
```bash
# SSH into your server
ssh root@your-server-ip

# Download the suite
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh

# Make executable
chmod +x ssh-management-suite.sh

# Review the script (optional but recommended)
less ssh-management-suite.sh

# Run the suite
sudo ./ssh-management-suite.sh
```

### Step 2: Choose Your Operation

The suite will display the main menu:

```
SSH Management Suite v3.0
===============================
Host: your-hostname
Current SSH Port: 22

1) Harden SSH (new installation)
2) Configure multi-IP access  
3) Manage/rollback previous sessions
4) Validate current configuration
5) Exit
```

### Step 3A: Initial SSH Hardening (Option 1)

**For fresh LXC/VM installations:**

1. **Select Option 1** from the main menu
2. **Configure settings** when prompted:
   - Admin username (default: `admin`)
   - SSH port (default: `2222`)
   - Network restrictions (optional: `192.168.1.0/24`)
3. **Key generation** (recommended: both Ed25519 + RSA-4096)
4. **Apply hardening** (disables root login, passwords, etc.)
5. **Service restart** (handles socket activation automatically)

**Critical: Test connection immediately:**
```bash
# The script provides exact command like:
ssh -i /root/ssh-generated-keys-TIMESTAMP/admin_ed25519 -p 2222 admin@your-server-ip
```

### Step 3B: Multi-IP Configuration (Option 2)

**Perfect for MacBook users with office/home access:**

1. **Select Option 2** from the main menu
2. **Enter your username** (must exist on system)
3. **Add network ranges** one by one:
   ```
   Enter network/IP (empty to finish): 10.0.0.0/8        # Office/Teleport
   Enter network/IP (empty to finish): 192.168.1.0/24    # Home network 1
   Enter network/IP (empty to finish): 192.168.50.0/24   # Home network 2
   Enter network/IP (empty to finish): [press Enter]
   ```
4. **Review and apply** the configuration
5. **Test connections** from each location

### Step 3C: Rollback Management (Option 3)

**If you need to undo changes:**

1. **Select Option 3** from the main menu
2. **View available sessions** (automatically discovered)
3. **Choose a session** to examine details
4. **Execute rollback** (automated script + manual options)
5. **Verify restoration** (automatic SSH service restart)

### Step 3D: Configuration Validation (Option 4)

**To verify your SSH security:**

1. **Select Option 4** from the main menu
2. **Review test results** (port binding, security settings, etc.)
3. **Check recommendations** for any failed tests
4. **Get connection examples** for your current setup

### Step 4: Download SSH Keys

After initial hardening, you need to get your SSH keys:

#### Method A: SCP (Recommended)
```bash
# From your local machine (Mac/Linux)
mkdir -p ~/.ssh/proxmox-keys

# Download private key
scp -P 2222 admin@your-server-ip:/root/ssh-generated-keys-TIMESTAMP/admin_ed25519 ~/.ssh/proxmox-keys/

# Download key information (contains passphrases)
scp -P 2222 admin@your-server-ip:/root/ssh-generated-keys-TIMESTAMP/ALL_PUBLIC_KEYS.txt ~/.ssh/proxmox-keys/

# Set proper permissions
chmod 600 ~/.ssh/proxmox-keys/admin_ed25519
```

#### Method B: Copy-Paste (If SCP fails)
```bash
# On the server, display the private key
cat /root/ssh-generated-keys-TIMESTAMP/admin_ed25519

# On your local machine, create the key file
nano ~/.ssh/proxmox-keys/admin_ed25519
# Paste the key content, save with Ctrl+X, Y, Enter

# Set permissions
chmod 600 ~/.ssh/proxmox-keys/admin_ed25519

# Get the passphrase
cat /root/ssh-generated-keys-TIMESTAMP/ALL_PUBLIC_KEYS.txt
```

### Step 5: Configure SSH Client

#### Terminal/Command Line
```bash
# Add to ~/.ssh/config
nano ~/.ssh/config

# Add entry:
Host my-proxmox-server
    HostName your-server-ip
    Port 2222
    User admin
    IdentityFile ~/.ssh/proxmox-keys/admin_ed25519
    IdentitiesOnly yes

# Connect with:
ssh my-proxmox-server
```

#### Termius (macOS/iOS)
1. **Open Termius**
2. **Add new host:**
   - Alias: `Proxmox Server`
   - Hostname: `your-server-ip`
   - Port: `2222`
   - Username: `admin`
3. **Import key:** Settings → Keys → Import → Select private key
4. **Enter passphrase** from ALL_PUBLIC_KEYS.txt

### Step 6: Ongoing Management

The SSH Management Suite can be run anytime for:

- **Adding new network ranges** (Option 2)
- **Rolling back changes** (Option 3)  
- **Validating configuration** (Option 4)
- **Re-running hardening** (Option 1)

Simply run the suite again:
```bash
sudo ./ssh-management-suite.sh
```

## 🔄 Advanced Features

### Session Management
The suite automatically tracks all SSH modifications and provides comprehensive session management:

- **Session Discovery**: Automatically finds previous hardening sessions
- **Detailed History**: View exactly what changes were made when
- **Safe Rollbacks**: Test configurations before applying rollbacks
- **Selective Restoration**: Choose which parts to rollback

### Socket Activation Handling
Modern systemd systems use socket activation which can interfere with SSH port changes. The suite automatically:

- **Detects socket conflicts** that prevent port binding
- **Safely disables ssh.socket** when needed
- **Preserves rollback capability** for socket settings
- **Handles service dependencies** properly

### Multi-Location Access
Perfect for users who work from multiple locations:

```bash
# Example: MacBook user with office and home access
AllowUsers admin@10.0.0.0/8 admin@192.168.1.0/24 admin@192.168.50.0/24
```

This configuration allows SSH access from:
- **Office network**: 10.x.x.x (Teleport/UniFi/VPN)
- **Home network 1**: 192.168.1.x 
- **Home network 2**: 192.168.50.x

### Comprehensive Validation
The built-in validation system checks:

- **Service Status**: SSH daemon health and port binding
- **Security Settings**: Root login, password auth, key auth status
- **File Permissions**: Key files, authorized_keys, configuration files
- **Network Configuration**: Socket activation, port conflicts
- **User Access**: AllowUsers restrictions and authorized_keys setup

## 🚨 Emergency Recovery

### If Locked Out via SSH

**Option 1: Use Proxmox Console**
1. Access your LXC/VM via **Proxmox web interface** → Console
2. Run the rollback manager: `sudo ./ssh-management-suite.sh` → Option 3
3. Select your session and rollback

**Option 2: Direct Rollback Script**
1. Access via **Proxmox console**
2. Find rollback script: `ls /root/ssh-*-rollback-*.sh`
3. Execute: `sudo /root/ssh-hardening-rollback-TIMESTAMP.sh`

**Option 3: Manual SSH Config Restore**
1. Access via **Proxmox console**
2. Restore config: `sudo cp /root/ssh-*-backups-*/sshd_config.*.bak /etc/ssh/sshd_config`
3. Restart SSH: `sudo systemctl restart ssh`

### Connection Testing
Always test your connection before closing existing sessions:

```bash
# Test from a NEW terminal window while keeping current session open
ssh -i ~/.ssh/proxmox-keys/admin_ed25519 -p 2222 admin@your-server-ip

# If connection fails, use Proxmox console to rollback
```

## 🛡️ Security Features

### SSH Hardening Applied
When you run Option 1 (Harden SSH), the following security measures are applied:

**Authentication Security**:
- Root login: **DISABLED**
- Password authentication: **DISABLED**  
- Public key authentication: **ENABLED**
- Empty passwords: **DISABLED**

**Connection Security**:
- Custom SSH port (default: 2222)
- User access restrictions (AllowUsers)
- Maximum auth attempts: **3**
- Login grace time: **30 seconds**
- Client alive interval: **5 minutes**

**Protocol Security**:
- Modern encryption algorithms only
- Strong key exchange methods  
- Secure MAC algorithms
- Protocol version 2 enforced

**Service Security**:
- X11 forwarding: **DISABLED**
- Agent forwarding: **DISABLED**
- TCP forwarding: **DISABLED**
- Tunneling: **DISABLED**

### Key Management
- **Ed25519 keys**: Modern, quantum-resistant cryptography
- **RSA-4096 keys**: Legacy compatibility for older systems
- **Encrypted private keys**: Strong random passphrases (25+ characters)
- **Proper permissions**: 600 for private keys, 644 for public keys
- **Secure storage**: Keys stored in timestamped directories

## 🔧 Troubleshooting

### Common Issues

**SSH Connection Refused**
```bash
# Check if SSH is running on correct port
sudo netstat -tlnp | grep :2222
sudo systemctl status ssh

# If not running on correct port, use the suite:
sudo ./ssh-management-suite.sh
# Choose Option 4 (Validate) to diagnose issues
```

**Permission Denied (publickey)**
```bash
# Verify key permissions on local machine
chmod 600 ~/.ssh/proxmox-keys/admin_ed25519

# Test with verbose SSH output
ssh -i ~/.ssh/proxmox-keys/admin_ed25519 -p 2222 -v admin@your-server-ip

# Check authorized_keys on server
sudo cat /home/admin/.ssh/authorized_keys
sudo ls -la /home/admin/.ssh/
```

**Socket Activation Issues**
```bash
# The suite handles this automatically, but for manual fixes:
sudo systemctl stop ssh.socket
sudo systemctl disable ssh.socket  
sudo systemctl mask ssh.socket
sudo systemctl restart ssh
```

**Validation Failures**
```bash
# Run comprehensive validation
sudo ./ssh-management-suite.sh
# Choose Option 4 (Validate)

# Or use standalone validation
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-validation.sh | sudo bash
```

### Getting Help

1. **Run validation first**: Use Option 4 in the suite for detailed diagnostics
2. **Check service logs**: `sudo journalctl -u ssh -f`
3. **Test SSH config**: `sudo sshd -t`
4. **Use Proxmox console**: Always available as backup access method

## 📦 Repository Structure

```
proxmox-ssh-hardening/
├── ssh-management-suite.sh      # Main unified interface
├── ssh-validation.sh            # Standalone validation tool
├── README.md                    # This documentation
└── LICENSE                      # MIT License
```

## 🤝 Contributing

Contributions welcome! The suite is designed to be modular and extensible:

- **Bug reports**: Issues with specific distributions or edge cases
- **Feature requests**: Additional SSH security measures or convenience features  
- **Testing**: Validation on different Debian/Ubuntu versions
- **Documentation**: Usage examples and troubleshooting guides

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Acknowledgments

- Built for **Proxmox homelab environments**
- Optimized for **multi-location access scenarios**  
- Designed with **safety and recoverability** in mind
- Handles **modern systemd complexities** (socket activation, etc.)

---
Caution. Keep Proxmox console access available as a backup method.
