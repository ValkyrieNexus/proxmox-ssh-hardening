# proxmox-ssh-hardening
SSH hardening script for Proxmox LXC/VMs

Recommendation for initial installation:

# Download, Permissions, Execute

curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh_hardening.sh -o ssh-hardening.sh

chmod +x ssh-hardening.sh 

sudo ./ssh-hardening.sh

# 1. Download, View/Edit
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-config-manager.sh

chmod +x ssh-config-manager.sh

sudo ./ssh-config-manager.sh
