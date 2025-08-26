# Clone your repo locally
git clone https://github.com/ValkyrieNexus/proxmox-ssh-hardening.git
cd proxmox-ssh-hardening

# Create archive directory and move old files
mkdir archive
git mv ssh-hardening.sh archive/ 2>/dev/null || true
git mv ssh-config-manager.sh archive/ 2>/dev/null || true
git mv ssh-multi-ip-config.sh archive/ 2>/dev/null || true

# Create archive README
echo "# Archived Scripts

These scripts are deprecated. Use the SSH Management Suite instead:

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/ValkyrieNexus/proxmox-ssh-hardening/main/ssh-management-suite.sh | sudo bash
\`\`\`" > archive/README.md

# Commit changes
git add archive/
git commit -m "Archive deprecated scripts"
git push origin main
