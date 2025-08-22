# proxmox-ssh-hardening
SSH hardening script for Proxmox LXC/VMs

Recommendation for initial installation:

# Download, Permissions, Execute

curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh_hardening.sh -o ssh_hardening.sh

chmod +x ssh_hardening.sh 

sudo ./ssh_hardening.sh

# 1. Download, View/Edit
wget https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-config-manager.sh

chmod +x ssh-config-manager.sh

sudo ./ssh-config-manager.sh
